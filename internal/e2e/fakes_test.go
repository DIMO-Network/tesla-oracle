package e2e

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/go-zerodev/abis"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
)

// The fakes below stand in for everything tesla-oracle talks to outside its own
// process: DIMO's JWT issuer, Tesla's OAuth and Fleet APIs, identity-api,
// device-definitions-api (and the DIMO auth it logs in with), and the chain
// (RPC, paymaster and bundler). Nothing else is faked: requests go through the
// real HTTP clients, go-transactions and go-zerodev.

// --- DIMO JWT issuer -------------------------------------------------------

type jwtIssuer struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newJWTIssuer(t *testing.T) *jwtIssuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &jwtIssuer{key: key}
	iss.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pub := key.PublicKey
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "e2e",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	}))
	t.Cleanup(iss.server.Close)
	return iss
}

// token returns a DIMO-style JWT for the wallet, the way dex issues them.
func (i *jwtIssuer) token(t *testing.T, wallet common.Address) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"ethereum_address": wallet.Hex(),
		"sub":              wallet.Hex(),
		"exp":              time.Now().Add(time.Hour).Unix(),
		"iat":              time.Now().Unix(),
	})
	tok.Header["kid"] = "e2e"
	s, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --- Tesla OAuth + Fleet API -----------------------------------------------

type fleetFixture struct {
	KeyPaired  bool
	VCP        bool
	Discounted bool
	Firmware   string
	Toggle     *bool
	Configured bool // fleet_telemetry_config already set
}

type fakeTesla struct {
	mu             sync.Mutex
	server         *httptest.Server
	accountVINs    map[string][]string // account -> VINs Tesla lists for it
	codeAccount    map[string]string   // auth code -> account
	tokenAccount   map[string]string   // access token -> account
	flushedRefresh map[string]bool     // refresh tokens Tesla answers with login_required
	fleet          map[string]fleetFixture
	refreshCalls   map[string]int
	wakes          int
	scopes         []string
}

func newFakeTesla(t *testing.T, scopes []string) *fakeTesla {
	f := &fakeTesla{
		accountVINs:    map[string][]string{},
		codeAccount:    map[string]string{},
		tokenAccount:   map[string]string{},
		flushedRefresh: map[string]bool{},
		fleet:          map[string]fleetFixture{},
		refreshCalls:   map[string]int{},
		scopes:         scopes,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/v3/token", f.token)
	mux.HandleFunc("/api/1/vehicles", f.listVehicles)
	mux.HandleFunc("/api/1/vehicles/fleet_status", f.fleetStatus)
	mux.HandleFunc("/api/1/vehicles/fleet_telemetry_config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"response": map[string]any{"updated_vehicles": 1}})
	})
	mux.HandleFunc("/api/1/vehicles/", f.vehicleSubresource)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// accessToken is a Tesla-shaped access token: a JWT carrying the granted scopes.
func (f *fakeTesla) accessToken(account string) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": account,
		"scp": f.scopes,
		"exp": time.Now().Add(8 * time.Hour).Unix(),
		"jti": strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	s, _ := tok.SignedString([]byte("tesla"))
	f.tokenAccount[s] = account
	return s
}

func (f *fakeTesla) addAccount(account string, vins ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accountVINs[account] = vins
}

// authCode returns a fresh single-use code for the account, as Tesla's
// consent redirect would.
func (f *fakeTesla) authCode(account string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	code := fmt.Sprintf("code-%s-%d", account, time.Now().UnixNano())
	f.codeAccount[code] = account
	return code
}

func (f *fakeTesla) setFleet(vin string, fx fleetFixture) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fleet[vin] = fx
}

func (f *fakeTesla) flushRefresh(refreshToken string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushedRefresh[refreshToken] = true
}

func (f *fakeTesla) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		account, ok := f.codeAccount[r.Form.Get("code")]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_auth_code"})
			return
		}
		delete(f.codeAccount, r.Form.Get("code")) // single use
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  f.accessToken(account),
			"refresh_token": "rt-" + account + "-" + strconv.FormatInt(time.Now().UnixNano(), 10),
			"expires_in":    28800,
			"token_type":    "Bearer",
		})
	case "refresh_token":
		rt := r.Form.Get("refresh_token")
		f.refreshCalls[rt]++
		if f.flushedRefresh[rt] {
			// Tesla's real answer for a login it has thrown away.
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login_required", "error_description": "user session flushed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  f.accessToken("refreshed"),
			"refresh_token": rt + "-next",
			"expires_in":    28800,
			"token_type":    "Bearer",
		})
	case "client_credentials":
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "partner-token", "expires_in": 28800, "token_type": "Bearer"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (f *fakeTesla) accountFor(r *http.Request) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	account, ok := f.tokenAccount[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	return account, ok
}

// listVehicles pages like Tesla's list endpoint: page and page_size, with
// pagination.next pointing at the next page (0 on the last one).
func (f *fakeTesla) listVehicles(w http.ResponseWriter, r *http.Request) {
	account, ok := f.accountFor(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	f.mu.Lock()
	vins := f.accountVINs[account]
	f.mu.Unlock()

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 100
	}
	start, end := (page-1)*size, page*size
	if start > len(vins) {
		start = len(vins)
	}
	if end > len(vins) {
		end = len(vins)
	}
	out := make([]map[string]any, 0, end-start)
	for i, vin := range vins[start:end] {
		out = append(out, map[string]any{"id": 1000 + start + i, "vehicle_id": 2000 + start + i, "vin": vin, "state": "online"})
	}
	next := 0
	if end < len(vins) {
		next = page + 1
	}
	writeJSON(w, http.StatusOK, map[string]any{"response": out, "pagination": map[string]any{"next": next}})
}

func (f *fakeTesla) fleetStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		VINs []string `json:"vins"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	paired, unpaired := []string{}, []string{}
	info := map[string]any{}
	for _, vin := range req.VINs {
		fx := f.fleet[vin]
		if fx.KeyPaired {
			paired = append(paired, vin)
		} else {
			unpaired = append(unpaired, vin)
		}
		vi := map[string]any{
			"firmware_version":                  fx.Firmware,
			"vehicle_command_protocol_required": fx.VCP,
			"discounted_device_data":            fx.Discounted,
			"fleet_telemetry_version":           "1.0.0",
			"total_number_of_keys":              3,
		}
		if fx.Toggle != nil {
			vi["safety_screen_streaming_toggle_enabled"] = *fx.Toggle
		}
		info[vin] = vi
	}
	writeJSON(w, http.StatusOK, map[string]any{"response": map[string]any{
		"key_paired_vins": paired, "unpaired_vins": unpaired, "vehicle_info": info,
	}})
}

func (f *fakeTesla) wakeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wakes
}

// vehicleSubresource serves /api/1/vehicles/{vin}/fleet_telemetry_config and
// /api/1/vehicles/{vin}/wake_up.
func (f *fakeTesla) vehicleSubresource(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/1/vehicles/"), "/")
	if len(parts) == 2 && parts[1] == "wake_up" {
		f.mu.Lock()
		f.wakes++
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"response": map[string]any{"id": 1, "vehicle_id": 2, "vin": parts[0], "state": "online"}})
		return
	}
	if len(parts) != 2 || parts[1] != "fleet_telemetry_config" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	f.mu.Lock()
	fx := f.fleet[parts[0]]
	f.mu.Unlock()
	if r.Method == http.MethodDelete {
		writeJSON(w, http.StatusOK, map[string]any{"response": map[string]any{"updated_vehicles": 1}})
		return
	}
	var config any
	if fx.Configured {
		config = map[string]any{"hostname": "telemetry.example", "port": 443}
	}
	writeJSON(w, http.StatusOK, map[string]any{"response": map[string]any{
		"synced": true, "config": config, "key_paired": fx.KeyPaired, "limit_reached": false,
	}})
}

// --- identity-api ------------------------------------------------------------

type idVehicle struct {
	owner     common.Address
	ddID      string
	sdTokenID int64
	visibleAt time.Time // identity-api hasn't indexed the mint before this
	// sdVisibleAt: identity-api shows the vehicle without its SD before this (an SD
	// minted onto an existing vehicle, not indexed yet).
	sdVisibleAt time.Time
}

type fakeIdentity struct {
	mu       sync.Mutex
	server   *httptest.Server
	vehicles map[int64]*idVehicle
}

var (
	vehicleQueryRe  = regexp.MustCompile(`vehicle\(tokenId: (\d+)\)`)
	vehiclesQueryRe = regexp.MustCompile(`vehicles\(filterBy: \{owner: "(0x[0-9a-fA-F]{40})"\}`)
	ddQueryRe       = regexp.MustCompile(`deviceDefinition\(by: \{id: "([^"]+)"\}\)`)
)

func newFakeIdentity(t *testing.T) *fakeIdentity {
	f := &fakeIdentity{vehicles: map[int64]*idVehicle{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.query))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdentity) setVehicle(tokenID int64, v idVehicle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vehicles[tokenID] = &v
}

func (f *fakeIdentity) vehicleJSON(tokenID int64, v *idVehicle) map[string]any {
	var sd any
	if v.sdTokenID != 0 && !time.Now().Before(v.sdVisibleAt) {
		sd = map[string]any{"id": "sd", "tokenId": v.sdTokenID, "mintedAt": time.Now().UTC().Format(time.RFC3339)}
	}
	return map[string]any{
		"id":              "v",
		"tokenId":         tokenID,
		"mintedAt":        time.Now().UTC().Format(time.RFC3339),
		"owner":           v.owner.Hex(),
		"definition":      map[string]any{"id": v.ddID, "make": "Tesla", "model": "Model Y", "year": 2025},
		"syntheticDevice": sd,
	}
}

func (f *fakeIdentity) query(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query string `json:"query"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()

	switch {
	case ddQueryRe.MatchString(req.Query):
		id := ddQueryRe.FindStringSubmatch(req.Query)[1]
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"deviceDefinition": map[string]any{
			"deviceDefinitionId": id,
			"manufacturer":       map[string]any{"name": "Tesla", "tokenId": 7},
			"model":              "Model Y",
			"year":               2025,
		}}})
	case vehiclesQueryRe.MatchString(req.Query):
		owner := common.HexToAddress(vehiclesQueryRe.FindStringSubmatch(req.Query)[1])
		nodes := []map[string]any{}
		for id, v := range f.vehicles {
			if v.owner == owner && !now.Before(v.visibleAt) {
				nodes = append(nodes, f.vehicleJSON(id, v))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"vehicles": map[string]any{
			"nodes":    nodes,
			"pageInfo": map[string]any{"hasNextPage": false, "hasPreviousPage": false},
		}}})
	case vehicleQueryRe.MatchString(req.Query):
		id, _ := strconv.ParseInt(vehicleQueryRe.FindStringSubmatch(req.Query)[1], 10, 64)
		v, ok := f.vehicles[id]
		if !ok || now.Before(v.visibleAt) {
			// identity-api's real answer for a token it hasn't indexed: 200 with an error.
			writeJSON(w, http.StatusOK, map[string]any{
				"errors": []map[string]any{{"message": fmt.Sprintf("No vehicle with token id %d.", id), "extensions": map[string]any{"code": "NOT_FOUND"}}},
				"data":   map[string]any{"vehicle": nil},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"vehicle": f.vehicleJSON(id, v)}})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"message": "unexpected query"}}})
	}
}

// --- device-definitions-api + the DIMO auth it logs in with --------------------

func newFakeDeviceDefinitions(t *testing.T, ddID string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/web3/generate_challenge", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"state": "s", "challenge": "sign me"})
	})
	mux.HandleFunc("/auth/web3/submit_challenge", func(w http.ResponseWriter, _ *http.Request) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()})
		s, _ := tok.SignedString([]byte("dimo"))
		writeJSON(w, http.StatusOK, map[string]any{"access_token": s, "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("/device-definitions/decode-vin", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"deviceDefinitionId": ddID})
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// --- chain: RPC, paymaster and bundler ---------------------------------------

type mintOutcome struct {
	vehicleID   int64
	sdID        int64
	owner       common.Address
	lostReceipt bool // the user operation lands but its receipt poll fails
	onMined     func()
}

type fakeChain struct {
	mu        sync.Mutex
	server    *httptest.Server
	registry  common.Address
	regABI    *abi.ABI
	acctABI   abi.ABI
	chainID   *big.Int
	next      []mintOutcome
	sent      map[string]mintOutcome // userOp hash -> outcome
	sendCalls int
}

func newFakeChain(t *testing.T, registryAddr common.Address, chainID int64) *fakeChain {
	regABI, err := registry.RegistryMetaData.ParseABI()
	if err != nil {
		t.Fatal(err)
	}
	acctABI, err := abi.JSON(strings.NewReader(abis.Eip1271Abi))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeChain{registry: registryAddr, regABI: regABI, acctABI: acctABI, chainID: big.NewInt(chainID), sent: map[string]mintOutcome{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.rpc))
	t.Cleanup(f.server.Close)
	return f
}

// expectMint queues what the next user operation mints.
func (f *fakeChain) expectMint(o mintOutcome) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next = append(f.next, o)
}

func (f *fakeChain) sendCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sendCalls
}

func (f *fakeChain) rpc(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, rpcErr := f.handle(req.Method, req.Params)
	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if rpcErr != "" {
		resp["error"] = map[string]any{"code": -32000, "message": rpcErr}
	} else {
		resp["result"] = result
	}
	writeJSON(w, http.StatusOK, resp)
}

func (f *fakeChain) handle(method string, params []json.RawMessage) (any, string) {
	switch method {
	case "eth_call":
		var msg struct {
			Data hexutil.Bytes `json:"data"`
		}
		_ = json.Unmarshal(params[0], &msg)
		if len(msg.Data) >= 4 && string(msg.Data[:4]) == string(f.acctABI.Methods["eip712Domain"].ID) {
			out, err := f.acctABI.Methods["eip712Domain"].Outputs.Pack(
				[1]byte{0x0f}, "Kernel", "0.3.1", f.chainID, common.HexToAddress("0x00000000000000000000000000000000000a11ce"), [32]byte{}, []*big.Int{},
			)
			if err != nil {
				return nil, err.Error()
			}
			return hexutil.Encode(out), ""
		}
		// EntryPoint.getNonce
		return hexutil.Encode(make([]byte, 32)), ""
	case "zd_getUserOperationGasPrice":
		gp := map[string]string{"maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0x3b9aca00"}
		return map[string]any{"slow": gp, "standard": gp, "fast": gp}, ""
	case "zd_sponsorUserOperation":
		return map[string]string{
			"callGasLimit": "0x10000", "paymasterVerificationGasLimit": "0x10000", "paymasterPostOpGasLimit": "0x1",
			"verificationGasLimit": "0x10000", "maxPriorityFeePerGas": "0x3b9aca00", "paymaster": "0x00000000000000000000000000000000000000fa",
			"maxFeePerGas": "0x3b9aca00", "paymasterData": "0x", "preVerificationGas": "0x10000",
		}, ""
	case "eth_sendUserOperation":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sendCalls++
		if len(f.next) == 0 {
			return nil, "fake chain: unexpected user operation"
		}
		o := f.next[0]
		f.next = f.next[1:]
		hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("op-%d-%d", f.sendCalls, time.Now().UnixNano())))
		f.sent[hash.Hex()] = o
		if o.onMined != nil {
			o.onMined()
		}
		return hash.Hex(), ""
	case "eth_getUserOperationReceipt":
		var hash string
		_ = json.Unmarshal(params[0], &hash)
		f.mu.Lock()
		o, ok := f.sent[common.HexToHash(hash).Hex()]
		f.mu.Unlock()
		if !ok || o.lostReceipt {
			return nil, "fake chain: receipt poll failed"
		}
		return f.receipt(hash, o)
	default:
		return nil, "fake chain: unsupported method " + method
	}
}

// receipt builds a user operation receipt whose registry logs are ABI-encoded
// exactly like the real VehicleNodeMintedWithDeviceDefinition and
// SyntheticDeviceNodeMinted events, so go-transactions decodes them for real.
func (f *fakeChain) receipt(hash string, o mintOutcome) (any, string) {
	vehicleEvt := f.regABI.Events["VehicleNodeMintedWithDeviceDefinition"]
	vehicleData, err := vehicleEvt.Inputs.NonIndexed().Pack("tesla_model-y_2025")
	if err != nil {
		return nil, err.Error()
	}
	sdEvt := f.regABI.Events["SyntheticDeviceNodeMinted"]
	sdData, err := sdEvt.Inputs.NonIndexed().Pack(big.NewInt(1), big.NewInt(o.sdID))
	if err != nil {
		return nil, err.Error()
	}
	txHash := crypto.Keccak256Hash([]byte(hash))
	logs := []ethtypes.Log{
		{
			Address: f.registry,
			Topics:  []common.Hash{vehicleEvt.ID, common.BigToHash(big.NewInt(7)), common.BigToHash(big.NewInt(o.vehicleID)), common.BytesToHash(o.owner.Bytes())},
			Data:    vehicleData,
			TxHash:  txHash,
		},
		{
			Address: f.registry,
			Topics:  []common.Hash{sdEvt.ID, common.BigToHash(big.NewInt(o.vehicleID)), common.BytesToHash(common.HexToAddress("0x5d").Bytes()), common.BytesToHash(o.owner.Bytes())},
			Data:    sdData,
			TxHash:  txHash,
		},
	}
	status := hexutil.Uint(1)
	return map[string]any{
		"userOpHash": hash,
		"success":    true,
		"logs":       logs,
		"receipt": map[string]any{
			"transactionHash": txHash.Hex(),
			"blockNumber":     "0x1",
			"logs":            logs,
			"status":          &status,
		},
	}, ""
}

// --- helpers -------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func mustURL(t *testing.T, raw string) url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return *u
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k, crypto.PubkeyToAddress(k.PublicKey)
}

// selfSignedPEM makes the DIS client TLS material bootstrap requires; DIS is
// never called in these tests.
func selfSignedPEM(t *testing.T) (certPEM, keyPEM string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}
