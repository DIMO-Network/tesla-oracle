# tesla-oracle

A Go microservice that connects Tesla vehicles to the [DIMO Network](https://dimo.org), handling vehicle onboarding, telemetry management, and command execution.

## 🚗 What is Tesla Oracle?

Tesla Oracle connects Tesla vehicles to the DIMO Network as blockchain-based devices. It provides:

- **Vehicle Onboarding**: Connects Tesla vehicles to the DIMO network as synthetic devices
- **Telemetry Management**: Subscribes to and manages Tesla vehicle data streams
- **Vehicle Commands**: Executes vehicle operations (lock/unlock, climate control, etc.)
- **Blockchain Integration**: Mints NFTs for vehicles and validates ownership
- **Credential Security**: Stores and manages Tesla Fleet API credentials with encryption


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

## Swagger

`make generate-swagger`

We use https://github.com/swaggo/swag with the fiber support. 

