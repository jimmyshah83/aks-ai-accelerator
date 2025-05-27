// Storage resources module
// ...storage-related resources will be moved here from main.bicep...

param storageAccounts_genaisadevcc01_name string = 'genaisadevcc01'

resource storageAccounts_genaisadevcc01_name_resource 'Microsoft.Storage/storageAccounts@2024-01-01' = {
  name: storageAccounts_genaisadevcc01_name
  location: 'canadacentral'
  sku: {
    name: 'Standard_LRS'
    tier: 'Standard'
  }
  kind: 'StorageV2'
  properties: {
    dnsEndpointType: 'Standard'
    defaultToOAuthAuthentication: false
    publicNetworkAccess: 'Disabled'
    allowCrossTenantReplication: false
    isLocalUserEnabled: false
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    largeFileSharesState: 'Enabled'
    networkAcls: {
      resourceAccessRules: [
        // ...existing code...
      ]
    }
    // ...existing code...
  }
}
