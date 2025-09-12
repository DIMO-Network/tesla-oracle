package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	shttp "github.com/DIMO-Network/shared/pkg/http"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
)

type IdentityAPIService interface {
	GetCachedVehicleByTokenID(tokenID int64) (*models.Vehicle, error)
	FetchVehicleByTokenID(tokenID int64) (*models.Vehicle, error)
	FetchVehiclesByWalletAddress(address string) ([]models.Vehicle, error)

	GetDeviceDefinitionByID(id string) (*models.DeviceDefinition, error)
	GetCachedDeviceDefinitionByID(id string) (*models.DeviceDefinition, error)
	FetchDeviceDefinitionByID(id string) (*models.DeviceDefinition, error)
}

type identityAPIService struct {
	apiURL     url.URL
	cache      *cache.Cache
	httpClient shttp.ClientWrapper
	logger     *zerolog.Logger
}

func NewIdentityAPIService(logger *zerolog.Logger, settings *config.Settings) IdentityAPIService {
	h := map[string]string{}
	h["Content-Type"] = "application/json"
	hcw, _ := shttp.NewClientWrapper("", "", 10*time.Second, h, false, shttp.WithRetry(3))

	// Initialize cache with a default expiration time of 10 minutes and cleanup interval of 15 minutes
	c := cache.New(10*time.Minute, 15*time.Minute)

	return &identityAPIService{
		httpClient: hcw,
		apiURL:     settings.IdentityAPIEndpoint,
		logger:     logger,
		cache:      c,
	}
}

func (i *identityAPIService) GetCachedVehicleByTokenID(tokenID int64) (*models.Vehicle, error) {
	if cachedResponse, found := i.cache.Get(fmt.Sprintf("vehicle_%s", strconv.FormatInt(tokenID, 10))); found {
		return cachedResponse.(*models.Vehicle), nil
	}

	return nil, errors.New("not found")
}

func (i *identityAPIService) FetchVehicleByTokenID(tokenID int64) (*models.Vehicle, error) {
	strTokenID := strconv.FormatInt(tokenID, 10)

	// GraphQL query
	graphqlQuery := fmt.Sprintf(VehicleByTokenIDQuery, strTokenID)

	body, err := i.Query(graphqlQuery)
	if err != nil {
		return nil, err
	}

	var af models.GraphQlData[models.SingleVehicle]

	if err = json.Unmarshal(body, &af); err != nil {
		return nil, err
	}

	// Store response in cache
	i.cache.Set(fmt.Sprintf("vehicle_%s", strTokenID), &af.Data.Vehicle, cache.DefaultExpiration)

	return &af.Data.Vehicle, nil
}

func (i *identityAPIService) FetchVehiclesByWalletAddress(walletAddress string) ([]models.Vehicle, error) {
	vehicles := []models.Vehicle{}
	pagedVehicles, err := i.FetchUserVehiclesPage(walletAddress, "")
	if err != nil {
		return nil, err
	}

	vehicles = append(vehicles, pagedVehicles.Nodes...)

	for pagedVehicles.PageInfo.HasNextPage {
		pagedVehicles, err = i.FetchUserVehiclesPage(walletAddress, pagedVehicles.PageInfo.EndCursor)
		if err != nil {
			return nil, err
		}

		vehicles = append(vehicles, pagedVehicles.Nodes...)
	}

	return vehicles, nil
}

func (i *identityAPIService) FetchUserVehiclesPage(walletAddress string, after string) (*models.PagedVehiclesNodes, error) {
	afterCursor := "null"
	if after != "" {
		afterCursor = "\"" + after + "\""
	}
	graphqlQuery := fmt.Sprintf(VehiclesByWalletAndCursorQuery, walletAddress, afterCursor)

	body, err := i.Query(graphqlQuery)
	if err != nil {
		return nil, err
	}

	var pagedVehicles models.GraphQlData[models.PagedVehicles]

	if err = json.Unmarshal(body, &pagedVehicles); err != nil {
		return nil, err
	}

	return &pagedVehicles.Data.VehicleNodes, nil
}

func (i *identityAPIService) GetDeviceDefinitionByID(id string) (*models.DeviceDefinition, error) {
	cached, err := i.GetCachedDeviceDefinitionByID(id)
	if err == nil {
		return cached, nil
	}

	return i.FetchDeviceDefinitionByID(id)
}

func (i *identityAPIService) GetCachedDeviceDefinitionByID(id string) (*models.DeviceDefinition, error) {
	if cachedResponse, found := i.cache.Get(fmt.Sprintf("dd_%s", id)); found {
		return cachedResponse.(*models.DeviceDefinition), nil
	}

	return nil, errors.New("not found")
}

func (i *identityAPIService) FetchDeviceDefinitionByID(id string) (*models.DeviceDefinition, error) {
	graphqlQuery := fmt.Sprintf(DeviceDefinitionByIDQuery, id)

	body, err := i.Query(graphqlQuery)
	if err != nil {
		return nil, err
	}

	var af models.GraphQlData[models.SingleDeviceDefinition]

	if err = json.Unmarshal(body, &af); err != nil {
		return nil, err
	}

	// Store response in cache
	i.cache.Set(fmt.Sprintf("dd_%s", id), &af.Data.DeviceDefinition, cache.DefaultExpiration)

	return &af.Data.DeviceDefinition, nil
}

func (i *identityAPIService) Query(graphqlQuery string) ([]byte, error) {
	requestPayload := models.GraphQLRequest{Query: graphqlQuery}
	payloadBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, err
	}

	resp, err := i.httpClient.ExecuteRequest(i.apiURL.String(), "POST", payloadBytes)
	if err != nil {
		i.logger.Err(err).Msg("Failed to send POST request")
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			i.logger.Err(err).Msg("Failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode == 400 {
		return nil, core.ErrBadRequest
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		i.logger.Err(err).Msgf("Failed to read response body")
		return nil, err
	}

	return body, nil
}

const DeviceDefinitionByIDQuery = `{
	deviceDefinition(by: {id: "%s"}) {
    	deviceDefinitionId
    	manufacturer {
      		name
      		tokenId
    	}
    	model
    	year
  	}
}`

const VehiclesByWalletAndCursorQuery = `{
  	vehicles(filterBy: {owner: "%s"}, first: 100, after: %s) {
		nodes {
			id
			tokenId
			mintedAt
			owner
			definition{
				id
				make
				model
				year
			}
			syntheticDevice {
			  	id
			  	tokenId
				mintedAt
			}
		}
    	pageInfo {
			hasPreviousPage
			hasNextPage
			startCursor
			endCursor
    	}
  	}
}`

const VehicleByTokenIDQuery = `{
	vehicle(tokenId: %s) {
		id
		tokenId
		mintedAt
		owner
		definition{
			id
			make
			model
			year
		}
		syntheticDevice {
			id
			tokenId
			mintedAt
			address
		}
  	}
}`
