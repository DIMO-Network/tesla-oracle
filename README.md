# tesla-oracle

A Go microservice that connects Tesla vehicles to the [DIMO Network](https://dimo.org), handling vehicle onboarding, telemetry management, and command execution.

## 🚗 What is Tesla Oracle?

Tesla Oracle connects Tesla vehicles to the DIMO Network as blockchain-based devices. It provides:

- **Vehicle Onboarding**: Connects Tesla vehicles to the DIMO network as synthetic devices
- **Telemetry Management**: Subscribes to and manages Tesla vehicle data streams
- **Vehicle Commands**: Executes vehicle operations (lock/unlock, climate control, etc.)
- **Blockchain Integration**: Mints NFTs for vehicles and validates ownership
- **Credential Security**: Stores and manages Tesla Fleet API credentials with encryption

## 🔄 Vehicle Onboarding Process

Tesla Oracle handles vehicle onboarding through a simplified API flow that replaces the previous devices-api integration.

### Onboarding Flow

```
Tesla Auth → List Vehicles → Virtual Key → Verify → Mint Data → Sign → Submit → Poll → Finalize
```

**Current Flow (backed by tesla-oracle)**:

1. **Authorize with Tesla** - OAuth flow with Tesla
2. **`POST /v1/vehicles`** - Get owned vehicles (`vin`, `externalId`, `device_definition_id`, MMY)
3. **Select vehicle** from the list
4. **`GET /v1/virtual-key?vin=<vin>`** - Check virtual key pairing status
5. **Depending on the status handle virtual key step with Tesla app**
6. **`POST /v1/vehicle/verify`** - Verify vehicle with `{vins: [vin]}` payload
7. **`GET /v1/vehicle/mint?vins=<vin>`** - Get signing payload for the VIN
8. **Sign the payload** - EIP-712 signature + SACD creation
9. **`POST /v1/vehicle/mint`** - Submit signed data:
   ```json
   {
     "vinMintingData": [
       {"vin": "...", "signature": "0x...", "typedData": {}, "sacd": "..."}
     ]
   }
   ```
10. **`GET /v1/vehicle/mint/status?vins=<vin>`** - Poll for mint completion
11. **`POST /v1/vehicle/finalize`** - Complete onboarding with `{vins: [vin]}`
12. **Response**: `{vehicles: [{vin, vehicleTokenId, syntheticTokenId}]}`

**WebView Integration Flow**:

1. **Open WebView** with oracle UI URL + JWT + optional vehicle token ID
2. **Listen for messages**:
   - `open` - Open URL for virtual key pairing
   - `sign-mint` - Sign typed data and add SACD to response
   - `onboarded` - Receive VIN, vehicle token ID, and synthetic device token ID
3. **Close WebView** and continue with app flow

## 🧠 Business Logic & Status Responses

Tesla Oracle uses decision trees to determine vehicle status and next actions based on Tesla Fleet API data.

### Status Endpoint Examples

#### **Ready to Start Data Flow**
```json
{
  "message": "Vehicle ready to start data flow. Submit command to start telemetry",
  "action": "set_telemetry_config",
  "next": {
    "method": "POST",
    "endpoint": "/v1/commands/123",
    "body": {"command": "telemetry/start"}
  }
}
```

#### **Virtual Key Not Paired**
```json
{
  "message": "Virtual key not paired. Open Tesla app deeplink for pairing.",
  "action": "open_tesla_deeplink"
}
```

#### **Firmware Too Old**
```json
{
  "message": "Firmware too old. Please update to 2025.20 or higher.",
  "action": "update_firmware"
}
```

#### **Streaming Toggle Disabled**
```json
{
  "message": "Streaming toggle disabled. Prompt user to enable it.",
  "action": "prompt_toggle"
}
```

#### **Already Configured**
```json
{
  "message": "Telemetry configuration already set, no need to call /start endpoint",
  "action": "telemetry_configured"
}
```

### Telemetry Operations

All telemetry operations are now available via the commands endpoint:
- **Subscribe**: `POST /v1/commands/{tokenID}` with `{"command": "telemetry/subscribe"}` - Requires `MobileAppDevLicense` wallet (dev license validation)
- **Unsubscribe**: `POST /v1/commands/{tokenID}` with `{"command": "telemetry/unsubscribe"}` - Requires `MobileAppDevLicense` wallet (dev license validation)
- **Start Data Flow**: `POST /v1/commands/{tokenID}` with `{"command": "telemetry/start"}` - Requires vehicle ownership validation
- **Wake Up**: `POST /v1/commands/{tokenID}` with `{"command": "wakeup"}` - Wakes up vehicle from sleep
- **Vehicle Commands**: `POST /v1/commands/{tokenID}` with commands like `frunk/open`, `doors/lock`, etc. - Require active telemetry subscription status + privilege token authentication

## ⚡ Background Processing with River Jobs

Tesla Oracle uses [River](https://riverqueue.com/) job queue system for asynchronous processing of complex operations such as onboarding or commands.

### Onboarding Jobs

**OnboardingWorker** handles vehicle minting operations:

- **Job Type**: `OnboardingArgs`
- **Timeout**: 30 minutes for complex blockchain operations
- **Max Attempts**: 1 (fail-fast approach)
- **Unique Jobs**: Prevents duplicate processing for the same VIN
- **Processing**:
  - Validates onboarding record and status
  - Generates synthetic device wallets if needed
  - Executes blockchain transactions (Vehicle NFT + Synthetic Device NFT minting)
  - Updates status throughout the process
  - Handles failure scenarios with proper rollback

### Command Jobs

**CommandWorker** handles Tesla vehicle command execution:

- **Job Type**: `CommandArgs`
- **Timeout**: Configurable based on command type
- **Max Attempts**: Configurable retry logic
- **Processing**:
  - Retrieves and decrypts Tesla credentials
  - Executes commands via Tesla Fleet API (lock/unlock, climate control, etc.)
  - Handles Tesla API rate limiting and errors
  - Updates command status and results
  - Manages credential refresh if needed

**Architecture Improvement**: The River jobs for commands simplified the legacy task-worker devices-api → task-worker approach by eliminating Kafka dependency and performing async operations completely within the service itself.

## 🌐 External Integrations
### Tesla Fleet API
- Vehicle data retrieval and management
- Telemetry subscription/unsubscription
- Virtual key status monitoring
- Command execution

### DIMO Network Services
- **Identity API**: User and device identity management
- **Device Definitions API**: Vehicle metadata and specifications
- **Synthetic Wallets API**: Blockchain transaction management
- **Devices gRPC**: Task and workflow coordination

### Blockchain (Ethereum)
- Vehicle NFT minting and ownership validation
- Smart contract event processing
- Wallet-based authentication and authorization

### Kafka Integration

**Credential Listener**: Tesla Oracle consumes credential updates from the DIMO network via Kafka:

- **Topic**: `CREDENTIAL_KTABLE` (configured per environment)
- **Consumer Group**: `tesla-oracle`
- **Purpose**: Receives Tesla API credential updates for synthetic devices
- **Processing**:
  - Listens for credential cloud events with access/refresh tokens
  - Updates `synthetic_devices` table with new encrypted credentials
  - Handles token expiry management (access tokens + 90-day refresh tokens)
  - Filters for Tesla integration (IntegrationTokenID = 2)

**Contract Event Consumer**: Processes blockchain events when enabled:
- **Topic**: Configurable contract event topic
- **Purpose**: Handles smart contract events and state changes

## Swagger

`make generate-swagger`

We use https://github.com/swaggo/swag with the fiber support. 

## Running locally

Frontend:

1. Add an entry to hosts file: `127.0.0.1 localtesla.dimo.org`. This is the host used in vite.config.js
2. `cd web`
3. `npm i` - used to install all deps in package.json
4. `npm run dev` - runs the local web server - but still need local backend

If you don't want to run a local backend, you can point this to the production oracle by changing the `api-service.ts` file under
`getBaseUrl()` to `return "https://tesla-oracle.dimo.zone"`. For this to work, the backend must have localtesla.dimo.org:4443 as an 
allowed origin for CORS in go fiber and/or in helm charts `nginx.ingress.kubernetes.io/cors-allow-origin: ... https://localtesla.dimo.org:4443`.

Dev background:
Uses lit framework: https://lit.dev/playground/ thin layer on top of native web components. 

Backend:

1. `cp settings.sample.yaml settings.yaml`
2. Update settings.yaml with required secrets from production or dev
3. Run the db migrations `make migrate`
4. `go run ./cmd/tesla-oracle`
5. Update the `api-service.ts` -> `getBaseUrl()` function to return the locally running url.
6. Note that backend must be running under https using the same certs as in vite.config