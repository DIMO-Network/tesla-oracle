package service

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
