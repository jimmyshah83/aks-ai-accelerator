// API Management resources module
// ...API Management-related resources will be moved here from main.bicep...

param service_genai_gateway_apim_dev_cc_01_name string = 'genai-gateway-apim-dev-cc-01'
param apis_aks_store_front_path string
param virtualNetworks_genai_accelerator_vnet_dev_cc_01_name string = 'genai-accelerator-vnet-dev-cc-01'
param networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name string = 'genai-app-subnet-nsg-dev-cc-01'

resource service_genai_gateway_apim_dev_cc_01_name_resource 'Microsoft.ApiManagement/service@2024-06-01-preview' = {
  name: service_genai_gateway_apim_dev_cc_01_name
  location: 'Canada Central'
  sku: {
    name: 'Developer'
    capacity: 1
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publisherEmail: 'jimmyshah@microsoft.com'
    publisherName: 'Contoso'
    notificationSenderEmail: 'apimgmt-noreply@mail.windowsazure.com'
    hostnameConfigurations: [
      {
        type: 'Proxy'
        hostName: '${service_genai_gateway_apim_dev_cc_01_name}.azure-api.net'
        negotiateClientCertificate: false
        defaultSslBinding: true
        certificateSource: 'BuiltIn'
      }
    ]
    virtualNetworkConfiguration: {
      subnetResourceId: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet.id
    }
    customProperties: {
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': 'False'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11': 'False'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30': 'False'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168': 'False'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10': 'False'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11': 'False'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30': 'False'
      'Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2': 'False'
    }
    virtualNetworkType: 'External'
    disableGateway: false
    natGatewayState: 'Unsupported'
    apiVersionConstraint: {}
    publicNetworkAccess: 'Enabled'
    legacyPortalStatus: 'Disabled'
    developerPortalStatus: 'Enabled'
    releaseChannel: 'Default'
  }
}

resource service_genai_gateway_apim_dev_cc_01_name_aks_store_front 'Microsoft.ApiManagement/service/apis@2024-06-01-preview' = {
  parent: service_genai_gateway_apim_dev_cc_01_name_resource
  name: 'aks-store-front'
  properties: {
    displayName: 'AKS Store Front'
    apiRevision: '1'
    subscriptionRequired: false
    protocols: [
      'https'
    ]
    authenticationSettings: {
      oAuth2AuthenticationSettings: []
      openidAuthenticationSettings: []
    }
    subscriptionKeyParameterNames: {
      header: 'Ocp-Apim-Subscription-Key'
      query: 'subscription-key'
    }
    isCurrent: true
    path: apis_aks_store_front_path
  }
}

resource virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource
  name: 'app-subnet'
  properties: {
    addressPrefixes: [
      '10.0.0.0/24'
    ]
    networkSecurityGroup: {
      id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource.id
    }
    delegations: []
    privateEndpointNetworkPolicies: 'Disabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
  }
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    securityRules: [
      // ...security rules as in main.bicep...
    ]
  }
}

resource virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name
  location: 'canadacentral'
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
    // ...other subnet definitions as in main.bicep...
  }
}
// ...move all other APIM resources here as needed...
