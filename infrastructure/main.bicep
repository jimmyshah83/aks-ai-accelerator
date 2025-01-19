param location string

resource rgAksGenaiAccelerator 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-aks-genai-accelerator'
  location: 'eastus'
  tags: {}
}

module myModule 'integration-svc.bicep' = {
  name: 'myModuleInstance'
  params: {
    apiManagementName: 'myApiManagement'
    publisherEmail: 'myEmail'
    publisherName: 'myName'
  }
}


