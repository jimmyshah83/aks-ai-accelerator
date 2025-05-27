param di_accelerator_vnet_dev_cc_01_name string = 'di-accelerator-vnet-dev-cc-01'
param location string = 'canadacentral'

resource di_accelerator_vnet_dev_cc_01_name_resource 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: di_accelerator_vnet_dev_cc_01_name
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/22'
      ]
    }
    encryption: {
      enabled: false
      enforcement: 'AllowUnencrypted'
    }
    privateEndpointVNetPolicies: 'Disabled'
    subnets: [
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefixes: [
            '10.0.1.0/26'
          ]
          delegations: []
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
        type: 'Microsoft.Network/virtualNetworks/subnets'
      }
      {
        name: 'app-subnet'
        properties: {
          addressPrefixes: [
            '10.0.0.0/24'
          ]
          delegations: []
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
        type: 'Microsoft.Network/virtualNetworks/subnets'
      }
    ]
    virtualNetworkPeerings: []
    enableDdosProtection: false
  }
}

resource di_accelerator_vnet_dev_cc_01_name_app_subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: di_accelerator_vnet_dev_cc_01_name_resource
  name: 'app-subnet'
  properties: {
    addressPrefixes: [
      '10.0.0.0/24'
    ]
    delegations: []
    privateEndpointNetworkPolicies: 'Disabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
  }
}

resource di_accelerator_vnet_dev_cc_01_name_AzureBastionSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: di_accelerator_vnet_dev_cc_01_name_resource
  name: 'AzureBastionSubnet'
  properties: {
    addressPrefixes: [
      '10.0.1.0/26'
    ]
    delegations: []
    privateEndpointNetworkPolicies: 'Disabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
  }
}
