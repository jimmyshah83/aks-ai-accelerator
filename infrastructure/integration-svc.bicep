param apiManagementName string
param location string = resourceGroup().location
param publisherEmail string
param publisherName string
param skuName string = 'Developer'

resource apiManagement 'Microsoft.ApiManagement/service@2021-08-01' = {
  name: apiManagementName
  location: location
  sku: {
    name: skuName
    capacity: 1
  }
  properties: {
    publisherEmail: publisherEmail
    publisherName: publisherName
  }
}

output apiManagementId string = apiManagement.id
