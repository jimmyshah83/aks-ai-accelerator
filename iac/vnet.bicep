param di_accelerator_vnet_dev_cc_01_name string = 'di-accelerator-vnet-dev-cc-01'
param networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_externalid string = '/subscriptions/57123c17-af1a-4ec2-9494-a214fb148bf4/resourceGroups/rg-di-accelerator-dev-cc-01/providers/Microsoft.Network/networkSecurityGroups/di-app-subnet-nsg-dev-cc-01'
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
        // id: di_accelerator_vnet_dev_cc_01_name_AzureBastionSubnet.id
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
        // id: di_accelerator_vnet_dev_cc_01_name_app_subnet.id
        properties: {
          addressPrefixes: [
            '10.0.0.0/24'
          ]
          networkSecurityGroup: {
            id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_externalid
          }
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
    networkSecurityGroup: {
      id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_externalid
    }
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
