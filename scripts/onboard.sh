#!/usr/bin/env bash
# onboard.sh — drive the full Tesla vehicle onboarding flow from the command line.
#
# Prerequisites (all must be on PATH):
#   curl, jq
#   cast  (Foundry — https://book.getfoundry.sh/getting-started/installation)
#         OR  python3 with eth-account:  pip install eth-account
#
# Usage:
#   export PRIVATE_KEY=0x<your-eth-private-key>
#   export TESLA_AUTH_CODE=<code from Tesla OAuth redirect>
#   export VIN=<17-char VIN>
#   export ORACLE_URL=http://localhost:3555          # oracle base URL
#   export DIMO_AUTH_URL=https://auth.dimo.zone      # DIMO auth base URL
#   export DIMO_CLIENT_ID=0x<your-eth-address>       # same address as PRIVATE_KEY
#   export DIMO_DOMAIN=localhost                     # domain registered with DIMO auth
#   export TESLA_REDIRECT_URI=https://...            # must match what oracle expects
#
#   bash scripts/onboard.sh
#
# To get the Tesla auth code:
#   1. Call: GET $ORACLE_URL/v1/settings   (no auth needed)
#      It returns { authUrl, clientId, redirectUri, virtualKeyUrl }
#   2. Construct the authorization URL:
#      $authUrl?client_id=$clientId&redirect_uri=$redirectUri&response_type=code&scope=openid+vehicle_device_data+vehicle_cmds+vehicle_charging_cmds
#   3. Open that URL in any browser, log in with your Tesla account.
#   4. Tesla redirects to $redirectUri?code=<CODE>&...
#   5. Copy the CODE value — use it immediately (codes expire in ~30s).
#
# Virtual key note:
#   After GET /v1/virtual-key the response includes a `virtualKeyUrl` deep-link
#   (tesla://...).  Open it on a phone that has the Tesla app installed.  This is
#   a one-time step per vehicle.  After pairing you never need the app again.
#
# Signing note:
#   This script tries `cast wallet sign --typed-data` first (Foundry).
#   If cast is not available it falls back to a small Python snippet (eth-account).
#   You can also sign manually: paste the typed_data JSON into MetaMask (Sign
#   Typed Data v4) and paste the 0x-prefixed signature back when prompted.

set -euo pipefail

##############################################################################
# Helpers
##############################################################################

die() { echo "ERROR: $*" >&2; exit 1; }

require_env() {
  local var="$1"
  [[ -n "${!var:-}" ]] || die "$var is not set. See usage at the top of this script."
}

require_tool() {
  command -v "$1" &>/dev/null || die "'$1' not found on PATH. Install it and retry."
}

pretty() { echo; echo "==> $*"; }

##############################################################################
# Environment checks
##############################################################################

require_env PRIVATE_KEY
require_env TESLA_AUTH_CODE
require_env VIN
require_env ORACLE_URL
require_env DIMO_AUTH_URL
require_env DIMO_CLIENT_ID
require_env DIMO_DOMAIN
require_env TESLA_REDIRECT_URI

require_tool curl
require_tool jq

ORACLE_URL="${ORACLE_URL%/}"
DIMO_AUTH_URL="${DIMO_AUTH_URL%/}"

##############################################################################
# Step 0 — derive wallet address from private key
##############################################################################

pretty "Step 0 — resolving wallet address from PRIVATE_KEY"

if command -v cast &>/dev/null; then
  WALLET_ADDRESS=$(cast wallet address "$PRIVATE_KEY")
else
  # Fallback: use Python / eth-account
  WALLET_ADDRESS=$(python3 - <<PYEOF
from eth_account import Account
pk = "$PRIVATE_KEY"
if not pk.startswith("0x"):
    pk = "0x" + pk
print(Account.from_key(pk).address)
PYEOF
)
fi

echo "Wallet address: $WALLET_ADDRESS"

##############################################################################
# Step 1 — get DIMO JWT via Web3 challenge-response
#
# Challenge signing format (from internal/service/dimo_auth.go):
#   fullMsg = "\x19Ethereum Signed Message:\n" + len(challenge) + challenge
#   hash    = keccak256(fullMsg)
#   sig     = sign(hash, privateKey)
#   sig[64] += 27                (add 27 to the recovery byte)
#   encode as 0x-prefixed hex
#
# `cast wallet sign` does exactly this when you pass --no-hash (raw bytes
# already pre-hashed are not what we want) — actually, `cast wallet sign`
# performs the personal-sign prefix automatically, so we just pass the raw
# challenge string.
##############################################################################

pretty "Step 1 — requesting DIMO auth challenge"

CHALLENGE_RESP=$(curl -sf -X POST \
  "${DIMO_AUTH_URL}/auth/web3/generate_challenge?client_id=${DIMO_CLIENT_ID}&domain=${DIMO_DOMAIN}&scope=openid+email&response_type=code&address=${DIMO_CLIENT_ID}")

STATE=$(echo "$CHALLENGE_RESP" | jq -r '.state')
CHALLENGE=$(echo "$CHALLENGE_RESP" | jq -r '.challenge')

echo "Challenge state : $STATE"
echo "Challenge string: $CHALLENGE"

pretty "Step 1 — signing challenge"

if command -v cast &>/dev/null; then
  # cast wallet sign performs Ethereum personal-sign (prefix + keccak256) automatically
  SIG=$(cast wallet sign --private-key "$PRIVATE_KEY" "$CHALLENGE")
else
  SIG=$(python3 - <<PYEOF
from eth_account import Account
from eth_account.messages import encode_defunct

pk = "$PRIVATE_KEY"
if not pk.startswith("0x"):
    pk = "0x" + pk
msg = encode_defunct(text="""$CHALLENGE""")
signed = Account.sign_message(msg, private_key=pk)
print(signed.signature.hex() if isinstance(signed.signature, bytes) else signed.signature)
PYEOF
)
  # eth-account already adds 27 to the v byte for personal-sign
fi

echo "Signature: $SIG"

pretty "Step 1 — submitting challenge"

TOKEN_RESP=$(curl -sf -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${DIMO_CLIENT_ID}" \
  --data-urlencode "state=${STATE}" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "domain=${DIMO_DOMAIN}" \
  --data-urlencode "signature=${SIG}" \
  "${DIMO_AUTH_URL}/auth/web3/submit_challenge")

JWT=$(echo "$TOKEN_RESP" | jq -r '.access_token')
[[ -n "$JWT" && "$JWT" != "null" ]] || die "Failed to obtain JWT. Response: $TOKEN_RESP"
echo "JWT obtained (truncated): ${JWT:0:60}..."

AUTH_HEADER="Authorization: Bearer $JWT"

##############################################################################
# Step 2 — list vehicles / complete Tesla OAuth
#
# Sends the Tesla authorization code to the oracle. The oracle exchanges it
# for a Tesla access token and creates onboarding records in its database.
##############################################################################

pretty "Step 2 — POST /v1/vehicles (complete Tesla OAuth, list vehicles)"

VEHICLES_RESP=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{\"authorizationCode\": \"${TESLA_AUTH_CODE}\", \"redirectUri\": \"${TESLA_REDIRECT_URI}\"}" \
  "${ORACLE_URL}/v1/vehicles")

echo "$VEHICLES_RESP" | jq .
echo "$VEHICLES_RESP" | jq -e '.vehicles | length > 0' &>/dev/null \
  || die "No vehicles returned. Check that your Tesla auth code is valid and has not expired."

##############################################################################
# Step 3 — check virtual key status
#
# If status is not "paired", the response includes a virtualKeyUrl deep-link.
# Open it on a phone with the Tesla app to complete virtual key pairing, then
# re-run this script (the Tesla auth code will be expired by then — get a new
# one).
##############################################################################

pretty "Step 3 — GET /v1/virtual-key?vin=${VIN}"

VK_RESP=$(curl -sf \
  -H "$AUTH_HEADER" \
  "${ORACLE_URL}/v1/virtual-key?vin=${VIN}")

echo "$VK_RESP" | jq .

VK_STATUS=$(echo "$VK_RESP" | jq -r '.status // .virtualKeyStatus // "unknown"')
echo "Virtual key status: $VK_STATUS"

if [[ "$VK_STATUS" != "paired" && "$VK_STATUS" != "true" ]]; then
  VK_URL=$(echo "$VK_RESP" | jq -r '.virtualKeyUrl // empty')
  echo ""
  echo "Virtual key is not yet paired."
  if [[ -n "$VK_URL" ]]; then
    echo "Open this URL in the Tesla app to complete pairing:"
    echo "  $VK_URL"
  fi
  echo ""
  echo "After pairing: obtain a fresh Tesla auth code and re-run this script."
  echo "Continuing anyway — the verify step will tell you if pairing is required."
fi

##############################################################################
# Step 4 — verify VINs
##############################################################################

pretty "Step 4 — POST /v1/vehicle/verify"

VERIFY_RESP=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{\"vins\": [{\"vin\": \"${VIN}\"}]}" \
  "${ORACLE_URL}/v1/vehicle/verify")

echo "$VERIFY_RESP" | jq .

VERIFY_STATUS=$(echo "$VERIFY_RESP" | jq -r --arg vin "$VIN" \
  '.statuses[] | select(.vin == $vin) | .status')
[[ "$VERIFY_STATUS" == "Success" ]] \
  || die "Verify status for $VIN is '$VERIFY_STATUS'. Details: $(echo "$VERIFY_RESP" | jq -r --arg vin "$VIN" '.statuses[] | select(.vin == $vin) | .details')"

##############################################################################
# Step 5 — get EIP-712 typed data for signing
##############################################################################

pretty "Step 5 — GET /v1/vehicle/mint?vins=${VIN}"

MINT_DATA_RESP=$(curl -sf \
  -H "$AUTH_HEADER" \
  "${ORACLE_URL}/v1/vehicle/mint?vins=${VIN}")

echo "$MINT_DATA_RESP" | jq .

TYPED_DATA=$(echo "$MINT_DATA_RESP" | jq -r --arg vin "$VIN" \
  '.vinMintingData[] | select(.vin == $vin) | .typedData')

[[ -n "$TYPED_DATA" && "$TYPED_DATA" != "null" ]] \
  || die "No typedData returned for $VIN"

TYPED_DATA_FILE=$(mktemp /tmp/typed_data_XXXXXX.json)
echo "$TYPED_DATA" > "$TYPED_DATA_FILE"
echo "Typed data written to: $TYPED_DATA_FILE"

##############################################################################
# Step 6 — sign the EIP-712 typed data
#
# Two options:
#   a) cast wallet sign --typed-data  (Foundry ≥0.2)
#   b) Python eth-account
#
# The result is a 0x-prefixed 65-byte hex signature.
#
# If you prefer to sign manually (e.g. with MetaMask):
#   1. Open browser console on any MetaMask-connected site.
#   2. Run:  ethereum.request({method:'eth_signTypedData_v4', params:['<your-address>', JSON.stringify(<typed-data>)]})
#   3. Paste the resulting 0x... string into MINT_SIGNATURE below and
#      re-run from Step 7 onward.
##############################################################################

pretty "Step 6 — signing EIP-712 typed data"

if command -v cast &>/dev/null; then
  MINT_SIGNATURE=$(cast wallet sign --private-key "$PRIVATE_KEY" \
    --typed-data "$TYPED_DATA_FILE")
else
  MINT_SIGNATURE=$(python3 - <<PYEOF
import json, sys
from eth_account import Account
from eth_account.structured_data.hashing import load_and_validate_structured_data

with open("$TYPED_DATA_FILE") as f:
    td = json.load(f)

pk = "$PRIVATE_KEY"
if not pk.startswith("0x"):
    pk = "0x" + pk

signed = Account.sign_typed_data(pk, td.get("domain", {}), td.get("types", {}), td.get("message", {}))
sig = signed.signature.hex()
if not sig.startswith("0x"):
    sig = "0x" + sig
print(sig)
PYEOF
)
fi

echo "Signature: $MINT_SIGNATURE"

rm -f "$TYPED_DATA_FILE"

##############################################################################
# Step 7 — submit signed data to trigger minting
##############################################################################

pretty "Step 7 — POST /v1/vehicle/mint (submit signature)"

SUBMIT_PAYLOAD=$(jq -n \
  --arg vin "$VIN" \
  --arg sig "$MINT_SIGNATURE" \
  --argjson td "$TYPED_DATA" \
  '{vinMintingData: [{vin: $vin, signature: $sig, typedData: $td}]}')

SUBMIT_RESP=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "$SUBMIT_PAYLOAD" \
  "${ORACLE_URL}/v1/vehicle/mint")

echo "$SUBMIT_RESP" | jq .

##############################################################################
# Step 8 — poll mint status until Success or Failure
##############################################################################

pretty "Step 8 — polling GET /v1/vehicle/mint/status?vins=${VIN}"

MAX_POLLS=30
POLL_INTERVAL=10
POLL_COUNT=0

while true; do
  STATUS_RESP=$(curl -sf \
    -H "$AUTH_HEADER" \
    "${ORACLE_URL}/v1/vehicle/mint/status?vins=${VIN}")

  MINT_STATUS=$(echo "$STATUS_RESP" | jq -r --arg vin "$VIN" \
    '.statuses[] | select(.vin == $vin) | .status')
  MINT_DETAILS=$(echo "$STATUS_RESP" | jq -r --arg vin "$VIN" \
    '.statuses[] | select(.vin == $vin) | .details')

  echo "  [$POLL_COUNT] status=$MINT_STATUS  details=$MINT_DETAILS"

  if [[ "$MINT_STATUS" == "Success" ]]; then
    break
  elif [[ "$MINT_STATUS" == "Failure" ]]; then
    die "Minting failed for $VIN. Details: $MINT_DETAILS"
  fi

  POLL_COUNT=$((POLL_COUNT + 1))
  if [[ $POLL_COUNT -ge $MAX_POLLS ]]; then
    die "Timed out waiting for mint to complete after $((MAX_POLLS * POLL_INTERVAL))s"
  fi

  sleep "$POLL_INTERVAL"
done

echo "Minting succeeded!"

##############################################################################
# Step 9 — finalize onboarding
##############################################################################

pretty "Step 9 — POST /v1/vehicle/finalize"

FINALIZE_RESP=$(curl -sf -X POST \
  -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d "{\"vins\": [\"${VIN}\"]}" \
  "${ORACLE_URL}/v1/vehicle/finalize")

echo "$FINALIZE_RESP" | jq .

VEHICLE_TOKEN_ID=$(echo "$FINALIZE_RESP" | jq -r --arg vin "$VIN" \
  '.vehicles[] | select(.vin == $vin) | .vehicleTokenId')
SD_TOKEN_ID=$(echo "$FINALIZE_RESP" | jq -r --arg vin "$VIN" \
  '.vehicles[] | select(.vin == $vin) | .syntheticTokenId')

echo ""
echo "============================================"
echo " Onboarding complete!"
echo "   VIN              : $VIN"
echo "   Vehicle token ID : $VEHICLE_TOKEN_ID"
echo "   SD token ID      : $SD_TOKEN_ID"
echo "============================================"

##############################################################################
# Optional Step 10 — confirm vehicle status
##############################################################################

if [[ -n "$VEHICLE_TOKEN_ID" && "$VEHICLE_TOKEN_ID" != "null" ]]; then
  pretty "Step 10 — GET /v1/${VEHICLE_TOKEN_ID}/status (confirmation)"
  curl -sf \
    -H "$AUTH_HEADER" \
    "${ORACLE_URL}/v1/${VEHICLE_TOKEN_ID}/status" | jq . || true
fi
