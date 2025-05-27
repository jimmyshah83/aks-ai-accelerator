// Network resources module

param networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name string = 'genai-app-subnet-nsg-dev-cc-01'
param privateDnsZones_private_contoso_com_name string = 'private.contoso.com'
param privateDnsZones_privatelink_blob_core_windows_net_name string = 'privatelink.blob.core.windows.net'
param privateDnsZones_privatelink_search_windows_net_name string = 'privatelink.search.windows.net'
param publicIPAddresses_genai_accelerator_vnet_dev_cc_01_bastion_name string = 'genai-accelerator-vnet-dev-cc-01-bastion'
param publicIPAddresses_genai_jumpbox_vm_01_ip_name string = 'genai-jumpbox-vm-01-ip'

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    securityRules: [
      // ...existing security rules as in main.bicep...
    ]
  }
}

resource privateDnsZones_private_contoso_com_name_resource 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: privateDnsZones_private_contoso_com_name
  location: 'global'
  properties: {}
}

resource privateDnsZones_privatelink_blob_core_windows_net_name_resource 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: privateDnsZones_privatelink_blob_core_windows_net_name
  location: 'global'
  properties: {}
}

resource privateDnsZones_privatelink_search_windows_net_name_resource 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: privateDnsZones_privatelink_search_windows_net_name
  location: 'global'
  properties: {}
}

resource publicIPAddresses_genai_accelerator_vnet_dev_cc_01_bastion_name_resource 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: publicIPAddresses_genai_accelerator_vnet_dev_cc_01_bastion_name
  location: 'canadacentral'
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    ipAddress: '4.205.228.178'
    publicIPAddressVersion: 'IPv4'
    publicIPAllocationMethod: 'Static'
    idleTimeoutInMinutes: 4
    ipTags: []
    ddosSettings: {
      protectionMode: 'VirtualNetworkInherited'
    }
  }
}

resource publicIPAddresses_genai_jumpbox_vm_01_ip_name_resource 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: publicIPAddresses_genai_jumpbox_vm_01_ip_name
  location: 'canadacentral'
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  zones: [
    '1'
  ]
  properties: {
    ipAddress: '4.172.230.243'
    publicIPAddressVersion: 'IPv4'
    publicIPAllocationMethod: 'Static'
    idleTimeoutInMinutes: 4
    ipTags: []
  }
}
