param managedClusters_genai_cluster_dev_cc_01_enabled bool
param storageAccounts_genaisadevcc01_name string = 'genaisadevcc01'
param grafana_grafana_20250124153100_name string = 'grafana-20250124153100'
param registries_genaiacrdevcc_name string = 'genaiacrdevcc'
param virtualMachines_genai_jumpbox_vm_01_name string = 'genai-jumpbox-vm-01'
param privateDnsZones_private_contoso_com_name string = 'private.contoso.com'
param privateEndpoints_genai_pe_dev_cc_01_name string = 'genai-pe-dev-cc-01'
param components_genai_insights_dev_cc_01_name string = 'genai-insights-dev-cc-01'
param searchServices_genai_search_dev_cc_01_name string = 'genai-search-dev-cc-01'
param sshPublicKeys_genai_jumpbox_vm_01_key_name string = 'genai-jumpbox-vm-01_key'
param privateEndpoints_genai_pe_sa_dev_cc_01_name string = 'genai-pe-sa-dev-cc-01'
param actionGroups_RecommendedAlertRules_AG_1_name string = 'RecommendedAlertRules-AG-1'
param publicIPAddresses_genai_jumpbox_vm_01_ip_name string = 'genai-jumpbox-vm-01-ip'
param accounts_defaultazuremonitorworkspace_cca_name string = 'defaultazuremonitorworkspace-cca'
param service_genai_gateway_apim_dev_cc_01_name string = 'genai-gateway-apim-dev-cc-01'
param networkInterfaces_genai_jumpbox_vm_0185_z1_name string = 'genai-jumpbox-vm-0185_z1'
param privateDnsZones_privatelink_search_windows_net_name string = 'privatelink.search.windows.net'
param managedClusters_genai_cluster_dev_cc_01_name string = 'genai-cluster-dev-cc-01'
param virtualNetworks_genai_accelerator_vnet_dev_cc_01_name string = 'genai-accelerator-vnet-dev-cc-01'
param privateDnsZones_privatelink_blob_core_windows_net_name string = 'privatelink.blob.core.windows.net'
param actionGroups_Application_Insights_Smart_Detection_name string = 'Application Insights Smart Detection'
param networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name string = 'genai-app-subnet-nsg-dev-cc-01'
param bastionHosts_genai_accelerator_vnet_dev_cc_01_Bastion_name string = 'genai-accelerator-vnet-dev-cc-01-Bastion'
param publicIPAddresses_genai_accelerator_vnet_dev_cc_01_bastion_name string = 'genai-accelerator-vnet-dev-cc-01-bastion'
param metricAlerts_CPU_Usage_Percentage_genai_cluster_dev_cc_01_name string = 'CPU Usage Percentage - genai-cluster-dev-cc-01'
param dataCollectionRules_MSCI_canadacentral_genai_cluster_dev_cc_01_name string = 'MSCI-canadacentral-genai-cluster-dev-cc-01'
param dataCollectionRules_MSProm_canadacentral_genai_cluster_dev_cc_01_name string = 'MSProm-canadacentral-genai-cluster-dev-cc-01'
param systemTopics_genaisadevcc01_28897de7_6b70_49e7_a640_0c7af22934f1_name string = 'genaisadevcc01-28897de7-6b70-49e7-a640-0c7af22934f1'
param dataCollectionEndpoints_MSProm_canadacentral_genai_cluster_dev_cc_01_name string = 'MSProm-canadacentral-genai-cluster-dev-cc-01'
param metricAlerts_Memory_Working_Set_Percentage_genai_cluster_dev_cc_01_name string = 'Memory Working Set Percentage - genai-cluster-dev-cc-01'
param smartdetectoralertrules_failure_anomalies_genai_insights_dev_cc_01_name string = 'failure anomalies - genai-insights-dev-cc-01'
param prometheusRuleGroups_NodeRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name string = 'NodeRecordingRulesRuleGroup-genai-cluster-dev-cc-01'
param prometheusRuleGroups_UXRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name string = 'UXRecordingRulesRuleGroup - genai-cluster-dev-cc-01'
param prometheusRuleGroups_NodeRecordingRulesRuleGroup_Win_genai_cluster_dev_cc_01_name string = 'NodeRecordingRulesRuleGroup-Win-genai-cluster-dev-cc-01'
param prometheusRuleGroups_UXRecordingRulesRuleGroup_Win_genai_cluster_dev_cc_01_name string = 'UXRecordingRulesRuleGroup-Win - genai-cluster-dev-cc-01'
param workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name string = '57123c17-af1a-4ec2-9494-a214fb148bf4-rg-genai-accelerator-CCAN'
param prometheusRuleGroups_KubernetesRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name string = 'KubernetesRecordingRulesRuleGroup-genai-cluster-dev-cc-01'
param prometheusRuleGroups_NodeAndKubernetesRecordingRulesRuleGroup_Win_genai_cluster_dev_c_name string = 'NodeAndKubernetesRecordingRulesRuleGroup-Win-genai-cluster-dev-c'
param solutions_ContainerInsights_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name string = 'ContainerInsights(57123c17-af1a-4ec2-9494-a214fb148bf4-rg-genai-accelerator-CCAN)'
param publicIPAddresses_31bf409f_46ce_4f56_bba4_df1db3877f0c_externalid string = '/subscriptions/57123c17-af1a-4ec2-9494-a214fb148bf4/resourceGroups/MC_rg-genai-accelerator-dev-cc-01_genai-cluster-dev-cc-01_canadacentral/providers/Microsoft.Network/publicIPAddresses/31bf409f-46ce-4f56-bba4-df1db3877f0c'
param userAssignedIdentities_genai_cluster_dev_cc_01_agentpool_externalid string = '/subscriptions/57123c17-af1a-4ec2-9494-a214fb148bf4/resourceGroups/MC_rg-genai-accelerator-dev-cc-01_genai-cluster-dev-cc-01_canadacentral/providers/Microsoft.ManagedIdentity/userAssignedIdentities/genai-cluster-dev-cc-01-agentpool'

resource sshPublicKeys_genai_jumpbox_vm_01_key_name_resource 'Microsoft.Compute/sshPublicKeys@2024-07-01' = {
  name: sshPublicKeys_genai_jumpbox_vm_01_key_name
  location: 'canadacentral'
  properties: {
    publicKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwz5hv9qmSbwcA7ghs8gUbUMA+bofaldsljAOYku8IEzwe/G2srXAmsEf2jIzmG3FH3xioh+ExVYKFs4CmH4OpD/y5gDPMy3Pyh8BEnoQ2M0IWLrlC8Q4vjgW+Vm/g57/ElSWzLJHPIs9bUM8ywGktX9WlOqDlwcLdHpBgHHBsZFPGGX9m/hKtTGFxDq7w+Pa/2kCEgqvssEbIXinJYFZ2V1FUrwfrLQU3FWmKARYjqnFfSUzmkYhcXzrjxs2NOoY46U8bBt+OUHQRm3MfJ8935ZYSwXHckAPdU2UpmlEZ6vp74MBLbL1Q7qlRhVRaFmKj3k00cAWF11mRrOcaK8Vgr+Tw7B0xBkWqNK1cPJd7TO3Sk9j5vMV+XoQ4hKgEGeHpuglxsKS/1sSlhbbvUkIL/ZDVd43wouXJ9t8VOyM2sRxDaPmRsaIn8FxxpISmdRiK8mGia+U2AsOlluMsaPxH+wMh60V4CubF9D/a+E2NWYkOzMNQhZM2xW7Rb1mt0O0= generated-by-azure'
  }
}

resource registries_genaiacrdevcc_name_resource 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: registries_genaiacrdevcc_name
  location: 'canadacentral'
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  properties: {
    adminUserEnabled: true
    policies: {
      quarantinePolicy: {
        status: 'disabled'
      }
      trustPolicy: {
        type: 'Notary'
        status: 'disabled'
      }
      retentionPolicy: {
        days: 7
        status: 'disabled'
      }
      exportPolicy: {
        status: 'enabled'
      }
      azureADAuthenticationAsArmPolicy: {
        status: 'enabled'
      }
      softDeletePolicy: {
        retentionDays: 7
        status: 'disabled'
      }
    }
    encryption: {
      status: 'disabled'
    }
    dataEndpointEnabled: false
    publicNetworkAccess: 'Enabled'
    networkRuleBypassOptions: 'AzureServices'
    zoneRedundancy: 'Disabled'
    anonymousPullEnabled: false
    metadataSearch: 'Disabled'
  }
}

resource actionGroups_Application_Insights_Smart_Detection_name_resource 'microsoft.insights/actionGroups@2023-09-01-preview' = {
  name: actionGroups_Application_Insights_Smart_Detection_name
  location: 'Global'
  properties: {
    groupShortName: 'SmartDetect'
    enabled: true
    emailReceivers: []
    smsReceivers: []
    webhookReceivers: []
    eventHubReceivers: []
    itsmReceivers: []
    azureAppPushReceivers: []
    automationRunbookReceivers: []
    voiceReceivers: []
    logicAppReceivers: []
    azureFunctionReceivers: []
    armRoleReceivers: [
      {
        name: 'Monitoring Contributor'
        roleId: '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
        useCommonAlertSchema: true
      }
      {
        name: 'Monitoring Reader'
        roleId: '43d0d8ad-25c7-4714-9337-8ba259a9fe05'
        useCommonAlertSchema: true
      }
    ]
  }
}

resource actionGroups_RecommendedAlertRules_AG_1_name_resource 'microsoft.insights/actionGroups@2023-09-01-preview' = {
  name: actionGroups_RecommendedAlertRules_AG_1_name
  location: 'Global'
  properties: {
    groupShortName: 'recalert1'
    enabled: true
    emailReceivers: [
      {
        name: 'Email_-EmailAction-'
        emailAddress: 'admin@MngEnvMCAP947289.onmicrosoft.com'
        useCommonAlertSchema: true
      }
    ]
    smsReceivers: []
    webhookReceivers: []
    eventHubReceivers: []
    itsmReceivers: []
    azureAppPushReceivers: []
    automationRunbookReceivers: []
    voiceReceivers: []
    logicAppReceivers: []
    azureFunctionReceivers: []
    armRoleReceivers: []
  }
}

resource dataCollectionEndpoints_MSProm_canadacentral_genai_cluster_dev_cc_01_name_resource 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dataCollectionEndpoints_MSProm_canadacentral_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  kind: 'Linux'
  properties: {
    immutableId: 'dce-8dc482946985466da3559904bf23f1b4'
    configurationAccess: {}
    logsIngestion: {}
    metricsIngestion: {}
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource accounts_defaultazuremonitorworkspace_cca_name_resource 'microsoft.monitor/accounts@2023-04-03' = {
  name: accounts_defaultazuremonitorworkspace_cca_name
  location: 'canadacentral'
  properties: {
    publicNetworkAccess: 'Enabled'
  }
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource 'Microsoft.Network/networkSecurityGroups@2024-03-01' = {
  name: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    securityRules: [
      {
        name: 'AllowTagCustom3443Inbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom3443Inbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          destinationPortRange: '3443'
          sourceAddressPrefix: 'ApiManagement'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowTagCustom443Inbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom443Inbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowTagCustom6390Inbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom6390Inbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          destinationPortRange: '6390'
          sourceAddressPrefix: 'AzureLoadBalancer'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowTtafficManager443Inbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTtafficManager443Inbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'AzureTrafficManager'
          destinationAddressPrefix: 'VirtualNetwork'
          access: 'Allow'
          priority: 130
          direction: 'Inbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowTagCustom443Outbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom443Outbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'Storage'
          access: 'Allow'
          priority: 140
          direction: 'Outbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowTagCustom1443Outbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom1443Outbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          destinationPortRange: '1443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'Sql'
          access: 'Allow'
          priority: 150
          direction: 'Outbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowKV443Outbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowKV443Outbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'AzureKeyVault'
          access: 'Allow'
          priority: 160
          direction: 'Outbound'
          sourcePortRanges: []
          destinationPortRanges: []
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
      {
        name: 'AllowTagCustom1886-443Outbound'
        id: networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom1886_443Outbound.id
        type: 'Microsoft.Network/networkSecurityGroups/securityRules'
        properties: {
          protocol: 'TCP'
          sourcePortRange: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: 'AzureMonitor'
          access: 'Allow'
          priority: 170
          direction: 'Outbound'
          sourcePortRanges: []
          destinationPortRanges: [
            '1886'
            '443'
          ]
          sourceAddressPrefixes: []
          destinationAddressPrefixes: []
        }
      }
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

resource publicIPAddresses_genai_accelerator_vnet_dev_cc_01_bastion_name_resource 'Microsoft.Network/publicIPAddresses@2024-03-01' = {
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

resource publicIPAddresses_genai_jumpbox_vm_01_ip_name_resource 'Microsoft.Network/publicIPAddresses@2024-03-01' = {
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

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name
  location: 'canadacentral'
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      legacy: 0
      searchVersion: 1
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: -1
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource searchServices_genai_search_dev_cc_01_name_resource 'Microsoft.Search/searchServices@2024-06-01-preview' = {
  name: searchServices_genai_search_dev_cc_01_name
  location: 'Canada Central'
  sku: {
    name: 'basic'
  }
  properties: {
    replicaCount: 1
    partitionCount: 1
    hostingMode: 'default'
    publicNetworkAccess: 'Disabled'
    networkRuleSet: {
      ipRules: []
      bypass: 'None'
    }
    encryptionWithCmk: {
      enforcement: 'Unspecified'
    }
    disableLocalAuth: false
    authOptions: {
      apiKeyOnly: {}
    }
    disabledDataExfiltrationOptions: []
    semanticSearch: 'free'
  }
}

resource storageAccounts_genaisadevcc01_name_resource 'Microsoft.Storage/storageAccounts@2023-05-01' = {
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
        {
          tenantId: 'c7b3a910-e2f8-4251-ac5c-d298df2d6e4e'
          resourceId: '/subscriptions/57123c17-af1a-4ec2-9494-a214fb148bf4/providers/Microsoft.Security/datascanners/StorageDataScanner'
        }
      ]
      bypass: 'AzureServices'
      virtualNetworkRules: []
      ipRules: []
      defaultAction: 'Deny'
    }
    supportsHttpsTrafficOnly: true
    encryption: {
      requireInfrastructureEncryption: false
      services: {
        file: {
          keyType: 'Account'
          enabled: true
        }
        blob: {
          keyType: 'Account'
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    accessTier: 'Hot'
  }
}

resource service_genai_gateway_apim_dev_cc_01_name_resource 'Microsoft.ApiManagement/service@2024-05-01' = {
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
  }
}

resource service_genai_gateway_apim_dev_cc_01_name_67941488217d2017e0634dda 'Microsoft.ApiManagement/service/properties@2019-01-01' = {
  parent: service_genai_gateway_apim_dev_cc_01_name_resource
  name: '67941488217d2017e0634dda'
  properties: {
    displayName: 'Logger-Credentials--67941488217d2017e0634ddb'
    value: '29dde703-249b-436c-81ac-5559099f412a'
    secret: true
  }
}

resource virtualMachines_genai_jumpbox_vm_01_name_resource 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: virtualMachines_genai_jumpbox_vm_01_name
  location: 'canadacentral'
  zones: [
    '1'
  ]
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    additionalCapabilities: {
      hibernationEnabled: false
    }
    storageProfile: {
      imageReference: {
        publisher: 'canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        osType: 'Linux'
        name: '${virtualMachines_genai_jumpbox_vm_01_name}_OsDisk_1_757a055b789b483e8fd8f3f1d3993d08'
        createOption: 'FromImage'
        caching: 'ReadWrite'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
          id: resourceId(
            'Microsoft.Compute/disks',
            '${virtualMachines_genai_jumpbox_vm_01_name}_OsDisk_1_757a055b789b483e8fd8f3f1d3993d08'
          )
        }
        deleteOption: 'Delete'
        diskSizeGB: 30
      }
      dataDisks: []
      diskControllerType: 'SCSI'
    }
    osProfile: {
      computerName: virtualMachines_genai_jumpbox_vm_01_name
      adminUsername: 'jimmyshah'
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/jimmyshah/.ssh/authorized_keys'
              keyData: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwz5hv9qmSbwcA7ghs8gUbUMA+bofaldsljAOYku8IEzwe/G2srXAmsEf2jIzmG3FH3xioh+ExVYKFs4CmH4OpD/y5gDPMy3Pyh8BEnoQ2M0IWLrlC8Q4vjgW+Vm/g57/ElSWzLJHPIs9bUM8ywGktX9WlOqDlwcLdHpBgHHBsZFPGGX9m/hKtTGFxDq7w+Pa/2kCEgqvssEbIXinJYFZ2V1FUrwfrLQU3FWmKARYjqnFfSUzmkYhcXzrjxs2NOoY46U8bBt+OUHQRm3MfJ8935ZYSwXHckAPdU2UpmlEZ6vp74MBLbL1Q7qlRhVRaFmKj3k00cAWF11mRrOcaK8Vgr+Tw7B0xBkWqNK1cPJd7TO3Sk9j5vMV+XoQ4hKgEGeHpuglxsKS/1sSlhbbvUkIL/ZDVd43wouXJ9t8VOyM2sRxDaPmRsaIn8FxxpISmdRiK8mGia+U2AsOlluMsaPxH+wMh60V4CubF9D/a+E2NWYkOzMNQhZM2xW7Rb1mt0O0= generated-by-azure'
            }
          ]
        }
        provisionVMAgent: true
        patchSettings: {
          patchMode: 'ImageDefault'
          assessmentMode: 'ImageDefault'
        }
      }
      secrets: []
      allowExtensionOperations: true
      requireGuestProvisionSignal: true
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterfaces_genai_jumpbox_vm_0185_z1_name_resource.id
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

resource registries_genaiacrdevcc_name_repositories_admin 'Microsoft.ContainerRegistry/registries/scopeMaps@2023-11-01-preview' = {
  parent: registries_genaiacrdevcc_name_resource
  name: '_repositories_admin'
  properties: {
    description: 'Can perform all read, write and delete operations on the registry'
    actions: [
      'repositories/*/metadata/read'
      'repositories/*/metadata/write'
      'repositories/*/content/read'
      'repositories/*/content/write'
      'repositories/*/content/delete'
    ]
  }
}

resource registries_genaiacrdevcc_name_repositories_pull 'Microsoft.ContainerRegistry/registries/scopeMaps@2023-11-01-preview' = {
  parent: registries_genaiacrdevcc_name_resource
  name: '_repositories_pull'
  properties: {
    description: 'Can pull any repository of the registry'
    actions: [
      'repositories/*/content/read'
    ]
  }
}

resource registries_genaiacrdevcc_name_repositories_pull_metadata_read 'Microsoft.ContainerRegistry/registries/scopeMaps@2023-11-01-preview' = {
  parent: registries_genaiacrdevcc_name_resource
  name: '_repositories_pull_metadata_read'
  properties: {
    description: 'Can perform all read operations on the registry'
    actions: [
      'repositories/*/content/read'
      'repositories/*/metadata/read'
    ]
  }
}

resource registries_genaiacrdevcc_name_repositories_push 'Microsoft.ContainerRegistry/registries/scopeMaps@2023-11-01-preview' = {
  parent: registries_genaiacrdevcc_name_resource
  name: '_repositories_push'
  properties: {
    description: 'Can push to any repository of the registry'
    actions: [
      'repositories/*/content/read'
      'repositories/*/content/write'
    ]
  }
}

resource registries_genaiacrdevcc_name_repositories_push_metadata_write 'Microsoft.ContainerRegistry/registries/scopeMaps@2023-11-01-preview' = {
  parent: registries_genaiacrdevcc_name_resource
  name: '_repositories_push_metadata_write'
  properties: {
    description: 'Can perform all read and write operations on the registry'
    actions: [
      'repositories/*/metadata/read'
      'repositories/*/metadata/write'
      'repositories/*/content/read'
      'repositories/*/content/write'
    ]
  }
}

resource managedClusters_genai_cluster_dev_cc_01_name_aksManagedAutoUpgradeSchedule 'Microsoft.ContainerService/managedClusters/maintenanceConfigurations@2024-08-01' = {
  parent: managedClusters_genai_cluster_dev_cc_01_name_resource
  name: 'aksManagedAutoUpgradeSchedule'
  properties: {
    maintenanceWindow: {
      schedule: {
        weekly: {
          intervalWeeks: 1
          dayOfWeek: 'Sunday'
        }
      }
      durationHours: 4
      utcOffset: '+00:00'
      startDate: '2025-01-25'
      startTime: '00:00'
    }
  }
}

resource managedClusters_genai_cluster_dev_cc_01_name_aksManagedNodeOSUpgradeSchedule 'Microsoft.ContainerService/managedClusters/maintenanceConfigurations@2024-08-01' = {
  parent: managedClusters_genai_cluster_dev_cc_01_name_resource
  name: 'aksManagedNodeOSUpgradeSchedule'
  properties: {
    maintenanceWindow: {
      schedule: {
        weekly: {
          intervalWeeks: 1
          dayOfWeek: 'Sunday'
        }
      }
      durationHours: 4
      utcOffset: '+00:00'
      startDate: '2025-01-25'
      startTime: '00:00'
    }
  }
}

resource grafana_grafana_20250124153100_name_resource 'microsoft.dashboard/grafana@2023-09-01' = {
  name: grafana_grafana_20250124153100_name
  location: 'canadacentral'
  sku: {
    name: 'Standard'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    zoneRedundancy: 'Disabled'
    publicNetworkAccess: 'Enabled'
    autoGeneratedDomainNameLabelScope: 'TenantReuse'
    apiKey: 'Disabled'
    deterministicOutboundIP: 'Disabled'
    grafanaIntegrations: {
      azureMonitorWorkspaceIntegrations: [
        {
          azureMonitorWorkspaceResourceId: accounts_defaultazuremonitorworkspace_cca_name_resource.id
        }
      ]
    }
    grafanaConfigurations: {
      smtp: {
        enabled: false
      }
    }
    grafanaMajorVersion: '10'
  }
}

resource systemTopics_genaisadevcc01_28897de7_6b70_49e7_a640_0c7af22934f1_name_resource 'Microsoft.EventGrid/systemTopics@2024-06-01-preview' = {
  name: systemTopics_genaisadevcc01_28897de7_6b70_49e7_a640_0c7af22934f1_name
  location: 'canadacentral'
  properties: {
    source: storageAccounts_genaisadevcc01_name_resource.id
    topicType: 'microsoft.storage.storageaccounts'
  }
}

resource systemTopics_genaisadevcc01_28897de7_6b70_49e7_a640_0c7af22934f1_name_StorageAntimalwareSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2024-06-01-preview' = {
  parent: systemTopics_genaisadevcc01_28897de7_6b70_49e7_a640_0c7af22934f1_name_resource
  name: 'StorageAntimalwareSubscription'
  properties: {
    destination: {
      properties: {
        maxEventsPerBatch: 1
        preferredBatchSizeInKilobytes: 64
        azureActiveDirectoryTenantId: '33e01921-4d64-4f8c-a055-5bdaffd5e33d'
        azureActiveDirectoryApplicationIdOrUri: 'f1f8da5f-609a-401d-85b2-d498116b7265'
      }
      endpointType: 'WebHook'
    }
    filter: {
      includedEventTypes: [
        'Microsoft.Storage.BlobCreated'
      ]
      advancedFilters: [
        {
          values: [
            'BlockBlob'
          ]
          operatorType: 'StringContains'
          key: 'data.blobType'
        }
      ]
    }
    eventDeliverySchema: 'EventGridSchema'
    retryPolicy: {
      maxDeliveryAttempts: 30
      eventTimeToLiveInMinutes: 1440
    }
  }
}

resource components_genai_insights_dev_cc_01_name_resource 'microsoft.insights/components@2020-02-02' = {
  name: components_genai_insights_dev_cc_01_name
  location: 'canadacentral'
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Flow_Type: 'Redfield'
    Request_Source: 'IbizaAIExtension'
    RetentionInDays: 90
    WorkspaceResourceId: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource components_genai_insights_dev_cc_01_name_degradationindependencyduration 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'degradationindependencyduration'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'degradationindependencyduration'
      DisplayName: 'Degradation in dependency duration'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_degradationinserverresponsetime 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'degradationinserverresponsetime'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'degradationinserverresponsetime'
      DisplayName: 'Degradation in server response time'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_digestMailConfiguration 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'digestMailConfiguration'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'digestMailConfiguration'
      DisplayName: 'Digest Mail Configuration'
      Description: 'This rule describes the digest mail preferences'
      HelpUrl: 'www.homail.com'
      IsHidden: true
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_extension_billingdatavolumedailyspikeextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'extension_billingdatavolumedailyspikeextension'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'extension_billingdatavolumedailyspikeextension'
      DisplayName: 'Abnormal rise in daily data volume (preview)'
      Description: 'This detection rule automatically analyzes the billing data generated by your application, and can warn you about an unusual increase in your application\'s billing costs'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/tree/master/SmartDetection/billing-data-volume-daily-spike.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_extension_canaryextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'extension_canaryextension'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'extension_canaryextension'
      DisplayName: 'Canary extension'
      Description: 'Canary extension'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/'
      IsHidden: true
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_extension_exceptionchangeextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'extension_exceptionchangeextension'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'extension_exceptionchangeextension'
      DisplayName: 'Abnormal rise in exception volume (preview)'
      Description: 'This detection rule automatically analyzes the exceptions thrown in your application, and can warn you about unusual patterns in your exception telemetry.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/abnormal-rise-in-exception-volume.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_extension_memoryleakextension 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'extension_memoryleakextension'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'extension_memoryleakextension'
      DisplayName: 'Potential memory leak detected (preview)'
      Description: 'This detection rule automatically analyzes the memory consumption of each process in your application, and can warn you about potential memory leaks or increased memory consumption.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/tree/master/SmartDetection/memory-leak.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_extension_securityextensionspackage 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'extension_securityextensionspackage'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'extension_securityextensionspackage'
      DisplayName: 'Potential security issue detected (preview)'
      Description: 'This detection rule automatically analyzes the telemetry generated by your application and detects potential security issues.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/application-security-detection-pack.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_extension_traceseveritydetector 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'extension_traceseveritydetector'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'extension_traceseveritydetector'
      DisplayName: 'Degradation in trace severity ratio (preview)'
      Description: 'This detection rule automatically analyzes the trace logs emitted from your application, and can warn you about unusual patterns in the severity of your trace telemetry.'
      HelpUrl: 'https://github.com/Microsoft/ApplicationInsights-Home/blob/master/SmartDetection/degradation-in-trace-severity-ratio.md'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_longdependencyduration 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'longdependencyduration'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'longdependencyduration'
      DisplayName: 'Long dependency duration'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_migrationToAlertRulesCompleted 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'migrationToAlertRulesCompleted'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'migrationToAlertRulesCompleted'
      DisplayName: 'Migration To Alert Rules Completed'
      Description: 'A configuration that controls the migration state of Smart Detection to Smart Alerts'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: true
      IsEnabledByDefault: false
      IsInPreview: true
      SupportsEmailNotifications: false
    }
    Enabled: false
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_slowpageloadtime 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'slowpageloadtime'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'slowpageloadtime'
      DisplayName: 'Slow page load time'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource components_genai_insights_dev_cc_01_name_slowserverresponsetime 'microsoft.insights/components/ProactiveDetectionConfigs@2018-05-01-preview' = {
  parent: components_genai_insights_dev_cc_01_name_resource
  name: 'slowserverresponsetime'
  location: 'canadacentral'
  properties: {
    RuleDefinitions: {
      Name: 'slowserverresponsetime'
      DisplayName: 'Slow server response time'
      Description: 'Smart Detection rules notify you of performance anomaly issues.'
      HelpUrl: 'https://docs.microsoft.com/en-us/azure/application-insights/app-insights-proactive-performance-diagnostics'
      IsHidden: false
      IsEnabledByDefault: true
      IsInPreview: false
      SupportsEmailNotifications: true
    }
    Enabled: true
    SendEmailsToSubscriptionOwners: true
    CustomEmails: []
  }
}

resource dataCollectionRules_MSCI_canadacentral_genai_cluster_dev_cc_01_name_resource 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dataCollectionRules_MSCI_canadacentral_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  kind: 'Linux'
  properties: {
    dataSources: {
      syslog: []
      extensions: [
        {
          streams: [
            'Microsoft-ContainerInsights-Group-Default'
          ]
          extensionName: 'ContainerInsights'
          extensionSettings: {
            dataCollectionSettings: {
              interval: '1m'
              namespaceFilteringMode: 'Off'
              enableContainerLogV2: true
            }
          }
          name: 'ContainerInsightsExtension'
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource.id
          name: 'ciworkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-ContainerInsights-Group-Default'
        ]
        destinations: [
          'ciworkspace'
        ]
      }
    ]
  }
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowKV443Outbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowKV443Outbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    destinationPortRange: '443'
    sourceAddressPrefix: 'VirtualNetwork'
    destinationAddressPrefix: 'AzureKeyVault'
    access: 'Allow'
    priority: 160
    direction: 'Outbound'
    sourcePortRanges: []
    destinationPortRanges: []
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom1443Outbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowTagCustom1443Outbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    destinationPortRange: '1443'
    sourceAddressPrefix: 'VirtualNetwork'
    destinationAddressPrefix: 'Sql'
    access: 'Allow'
    priority: 150
    direction: 'Outbound'
    sourcePortRanges: []
    destinationPortRanges: []
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom1886_443Outbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowTagCustom1886-443Outbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    sourceAddressPrefix: 'VirtualNetwork'
    destinationAddressPrefix: 'AzureMonitor'
    access: 'Allow'
    priority: 170
    direction: 'Outbound'
    sourcePortRanges: []
    destinationPortRanges: [
      '1886'
      '443'
    ]
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom3443Inbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowTagCustom3443Inbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    destinationPortRange: '3443'
    sourceAddressPrefix: 'ApiManagement'
    destinationAddressPrefix: 'VirtualNetwork'
    access: 'Allow'
    priority: 110
    direction: 'Inbound'
    sourcePortRanges: []
    destinationPortRanges: []
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom443Inbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowTagCustom443Inbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    destinationPortRange: '443'
    sourceAddressPrefix: 'Internet'
    destinationAddressPrefix: 'VirtualNetwork'
    access: 'Allow'
    priority: 100
    direction: 'Inbound'
    sourcePortRanges: []
    destinationPortRanges: []
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom443Outbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowTagCustom443Outbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    destinationPortRange: '443'
    sourceAddressPrefix: 'VirtualNetwork'
    destinationAddressPrefix: 'Storage'
    access: 'Allow'
    priority: 140
    direction: 'Outbound'
    sourcePortRanges: []
    destinationPortRanges: []
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTagCustom6390Inbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowTagCustom6390Inbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    destinationPortRange: '6390'
    sourceAddressPrefix: 'AzureLoadBalancer'
    destinationAddressPrefix: 'VirtualNetwork'
    access: 'Allow'
    priority: 120
    direction: 'Inbound'
    sourcePortRanges: []
    destinationPortRanges: []
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_AllowTtafficManager443Inbound 'Microsoft.Network/networkSecurityGroups/securityRules@2024-03-01' = {
  name: '${networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name}/AllowTtafficManager443Inbound'
  properties: {
    protocol: 'TCP'
    sourcePortRange: '*'
    destinationPortRange: '443'
    sourceAddressPrefix: 'AzureTrafficManager'
    destinationAddressPrefix: 'VirtualNetwork'
    access: 'Allow'
    priority: 130
    direction: 'Inbound'
    sourcePortRanges: []
    destinationPortRanges: []
    sourceAddressPrefixes: []
    destinationAddressPrefixes: []
  }
  dependsOn: [
    networkSecurityGroups_genai_app_subnet_nsg_dev_cc_01_name_resource
  ]
}

resource privateDnsZones_privatelink_blob_core_windows_net_name_genaisadevcc01 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: privateDnsZones_privatelink_blob_core_windows_net_name_resource
  name: 'genaisadevcc01'
  properties: {
    ttl: 3600
    aRecords: [
      {
        ipv4Address: '10.0.0.11'
      }
    ]
  }
}

resource privateDnsZones_privatelink_search_windows_net_name_genai_search_dev_cc_01 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: privateDnsZones_privatelink_search_windows_net_name_resource
  name: 'genai-search-dev-cc-01'
  properties: {
    ttl: 3600
    aRecords: [
      {
        ipv4Address: '10.0.0.12'
      }
    ]
  }
}

resource privateDnsZones_private_contoso_com_name_store_front 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: privateDnsZones_private_contoso_com_name_resource
  name: 'store-front'
  properties: {
    ttl: 300
    aRecords: [
      {
        ipv4Address: '10.0.0.10'
      }
    ]
  }
}

resource Microsoft_Network_privateDnsZones_SOA_privateDnsZones_private_contoso_com_name 'Microsoft.Network/privateDnsZones/SOA@2024-06-01' = {
  parent: privateDnsZones_private_contoso_com_name_resource
  name: '@'
  properties: {
    ttl: 3600
    soaRecord: {
      email: 'azureprivatedns-host.microsoft.com'
      expireTime: 2419200
      host: 'azureprivatedns.net'
      minimumTtl: 10
      refreshTime: 3600
      retryTime: 300
      serialNumber: 1
    }
  }
}

resource Microsoft_Network_privateDnsZones_SOA_privateDnsZones_privatelink_blob_core_windows_net_name 'Microsoft.Network/privateDnsZones/SOA@2024-06-01' = {
  parent: privateDnsZones_privatelink_blob_core_windows_net_name_resource
  name: '@'
  properties: {
    ttl: 3600
    soaRecord: {
      email: 'azureprivatedns-host.microsoft.com'
      expireTime: 2419200
      host: 'azureprivatedns.net'
      minimumTtl: 10
      refreshTime: 3600
      retryTime: 300
      serialNumber: 1
    }
  }
}

resource Microsoft_Network_privateDnsZones_SOA_privateDnsZones_privatelink_search_windows_net_name 'Microsoft.Network/privateDnsZones/SOA@2024-06-01' = {
  parent: privateDnsZones_privatelink_search_windows_net_name_resource
  name: '@'
  properties: {
    ttl: 3600
    soaRecord: {
      email: 'azureprivatedns-host.microsoft.com'
      expireTime: 2419200
      host: 'azureprivatedns.net'
      minimumTtl: 10
      refreshTime: 3600
      retryTime: 300
      serialNumber: 1
    }
  }
}

resource privateDnsZones_private_contoso_com_name_a_store_front 'Microsoft.Network/privateDnsZones/TXT@2024-06-01' = {
  parent: privateDnsZones_private_contoso_com_name_resource
  name: 'a-store-front'
  properties: {
    ttl: 300
    txtRecords: [
      {
        value: [
          '"heritage=external-dns,external-dns/owner=67940f624b8fff000121d2b5,external-dns/resource=ingress/phi-3-mini/inference-ingress"'
        ]
      }
    ]
  }
}

resource Microsoft_Network_privateDnsZones_TXT_privateDnsZones_private_contoso_com_name_store_front 'Microsoft.Network/privateDnsZones/TXT@2024-06-01' = {
  parent: privateDnsZones_private_contoso_com_name_resource
  name: 'store-front'
  properties: {
    ttl: 300
    txtRecords: [
      {
        value: [
          '"heritage=external-dns,external-dns/owner=67940f624b8fff000121d2b5,external-dns/resource=ingress/phi-3-mini/inference-ingress"'
        ]
      }
    ]
  }
}

resource virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource 'Microsoft.Network/virtualNetworks@2024-03-01' = {
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
    subnets: [
      {
        name: 'AzureBastionSubnet'
        id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_AzureBastionSubnet.id
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
        id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet.id
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
        type: 'Microsoft.Network/virtualNetworks/subnets'
      }
    ]
    virtualNetworkPeerings: []
    enableDdosProtection: false
  }
}

resource virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_AzureBastionSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-03-01' = {
  name: '${virtualNetworks_genai_accelerator_vnet_dev_cc_01_name}/AzureBastionSubnet'
  properties: {
    addressPrefixes: [
      '10.0.1.0/26'
    ]
    delegations: []
    privateEndpointNetworkPolicies: 'Disabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
  }
  dependsOn: [
    virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource
  ]
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_General_AlphabeticallySortedComputers 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_General|AlphabeticallySortedComputers'
  properties: {
    category: 'General Exploration'
    displayName: 'All Computers with their most recent data'
    version: 2
    query: 'search not(ObjectName == "Advisor Metrics" or ObjectName == "ManagedSpace") | summarize AggregatedValue = max(TimeGenerated) by Computer | limit 500000 | sort by Computer asc\r\n// Oql: NOT(ObjectName="Advisor Metrics" OR ObjectName=ManagedSpace) | measure max(TimeGenerated) by Computer | top 500000 | Sort Computer // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_General_dataPointsPerManagementGroup 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_General|dataPointsPerManagementGroup'
  properties: {
    category: 'General Exploration'
    displayName: 'Which Management Group is generating the most data points?'
    version: 2
    query: 'search * | summarize AggregatedValue = count() by ManagementGroupName\r\n// Oql: * | Measure count() by ManagementGroupName // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_General_dataTypeDistribution 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_General|dataTypeDistribution'
  properties: {
    category: 'General Exploration'
    displayName: 'Distribution of data Types'
    version: 2
    query: 'search * | extend Type = $table | summarize AggregatedValue = count() by Type\r\n// Oql: * | Measure count() by Type // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_General_StaleComputers 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_General|StaleComputers'
  properties: {
    category: 'General Exploration'
    displayName: 'Stale Computers (data older than 24 hours)'
    version: 2
    query: 'search not(ObjectName == "Advisor Metrics" or ObjectName == "ManagedSpace") | summarize lastdata = max(TimeGenerated) by Computer | limit 500000 | where lastdata < ago(24h)\r\n// Oql: NOT(ObjectName="Advisor Metrics" OR ObjectName=ManagedSpace) | measure max(TimeGenerated) as lastdata by Computer | top 500000 | where lastdata < NOW-24HOURS // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_AllEvents 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|AllEvents'
  properties: {
    category: 'Log Management'
    displayName: 'All Events'
    version: 2
    query: 'Event | sort by TimeGenerated desc\r\n// Oql: Type=Event // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_AllSyslog 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|AllSyslog'
  properties: {
    category: 'Log Management'
    displayName: 'All Syslogs'
    version: 2
    query: 'Syslog | sort by TimeGenerated desc\r\n// Oql: Type=Syslog // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_AllSyslogByFacility 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|AllSyslogByFacility'
  properties: {
    category: 'Log Management'
    displayName: 'All Syslog Records grouped by Facility'
    version: 2
    query: 'Syslog | summarize AggregatedValue = count() by Facility\r\n// Oql: Type=Syslog | Measure count() by Facility // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_AllSyslogByProcess 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|AllSyslogByProcessName'
  properties: {
    category: 'Log Management'
    displayName: 'All Syslog Records grouped by ProcessName'
    version: 2
    query: 'Syslog | summarize AggregatedValue = count() by ProcessName\r\n// Oql: Type=Syslog | Measure count() by ProcessName // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_AllSyslogsWithErrors 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|AllSyslogsWithErrors'
  properties: {
    category: 'Log Management'
    displayName: 'All Syslog Records with Errors'
    version: 2
    query: 'Syslog | where SeverityLevel == "error" | sort by TimeGenerated desc\r\n// Oql: Type=Syslog SeverityLevel=error // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_AverageHTTPRequestTimeByClientIPAddress 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|AverageHTTPRequestTimeByClientIPAddress'
  properties: {
    category: 'Log Management'
    displayName: 'Average HTTP Request time by Client IP Address'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = avg(TimeTaken) by cIP\r\n// Oql: Type=W3CIISLog | Measure Avg(TimeTaken) by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_AverageHTTPRequestTimeHTTPMethod 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|AverageHTTPRequestTimeHTTPMethod'
  properties: {
    category: 'Log Management'
    displayName: 'Average HTTP Request time by HTTP Method'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = avg(TimeTaken) by csMethod\r\n// Oql: Type=W3CIISLog | Measure Avg(TimeTaken) by csMethod // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_CountIISLogEntriesClientIPAddress 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|CountIISLogEntriesClientIPAddress'
  properties: {
    category: 'Log Management'
    displayName: 'Count of IIS Log Entries by Client IP Address'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by cIP\r\n// Oql: Type=W3CIISLog | Measure count() by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_CountIISLogEntriesHTTPRequestMethod 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|CountIISLogEntriesHTTPRequestMethod'
  properties: {
    category: 'Log Management'
    displayName: 'Count of IIS Log Entries by HTTP Request Method'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csMethod\r\n// Oql: Type=W3CIISLog | Measure count() by csMethod // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_CountIISLogEntriesHTTPUserAgent 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|CountIISLogEntriesHTTPUserAgent'
  properties: {
    category: 'Log Management'
    displayName: 'Count of IIS Log Entries by HTTP User Agent'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUserAgent\r\n// Oql: Type=W3CIISLog | Measure count() by csUserAgent // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_CountOfIISLogEntriesByHostRequestedByClient 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|CountOfIISLogEntriesByHostRequestedByClient'
  properties: {
    category: 'Log Management'
    displayName: 'Count of IIS Log Entries by Host requested by client'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csHost\r\n// Oql: Type=W3CIISLog | Measure count() by csHost // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_CountOfIISLogEntriesByURLForHost 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|CountOfIISLogEntriesByURLForHost'
  properties: {
    category: 'Log Management'
    displayName: 'Count of IIS Log Entries by URL for the host "www.contoso.com" (replace with your own)'
    version: 2
    query: 'search csHost == "www.contoso.com" | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUriStem\r\n// Oql: Type=W3CIISLog csHost="www.contoso.com" | Measure count() by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_CountOfIISLogEntriesByURLRequestedByClient 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|CountOfIISLogEntriesByURLRequestedByClient'
  properties: {
    category: 'Log Management'
    displayName: 'Count of IIS Log Entries by URL requested by client (without query strings)'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUriStem\r\n// Oql: Type=W3CIISLog | Measure count() by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_CountOfWarningEvents 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|CountOfWarningEvents'
  properties: {
    category: 'Log Management'
    displayName: 'Count of Events with level "Warning" grouped by Event ID'
    version: 2
    query: 'Event | where EventLevelName == "warning" | summarize AggregatedValue = count() by EventID\r\n// Oql: Type=Event EventLevelName=warning | Measure count() by EventID // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_DisplayBreakdownRespondCodes 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|DisplayBreakdownRespondCodes'
  properties: {
    category: 'Log Management'
    displayName: 'Shows breakdown of response codes'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by scStatus\r\n// Oql: Type=W3CIISLog | Measure count() by scStatus // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_EventsByEventLog 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|EventsByEventLog'
  properties: {
    category: 'Log Management'
    displayName: 'Count of Events grouped by Event Log'
    version: 2
    query: 'Event | summarize AggregatedValue = count() by EventLog\r\n// Oql: Type=Event | Measure count() by EventLog // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_EventsByEventsID 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|EventsByEventsID'
  properties: {
    category: 'Log Management'
    displayName: 'Count of Events grouped by Event ID'
    version: 2
    query: 'Event | summarize AggregatedValue = count() by EventID\r\n// Oql: Type=Event | Measure count() by EventID // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_EventsByEventSource 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|EventsByEventSource'
  properties: {
    category: 'Log Management'
    displayName: 'Count of Events grouped by Event Source'
    version: 2
    query: 'Event | summarize AggregatedValue = count() by Source\r\n// Oql: Type=Event | Measure count() by Source // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_EventsInOMBetween2000to3000 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|EventsInOMBetween2000to3000'
  properties: {
    category: 'Log Management'
    displayName: 'Events in the Operations Manager Event Log whose Event ID is in the range between 2000 and 3000'
    version: 2
    query: 'Event | where EventLog == "Operations Manager" and EventID >= 2000 and EventID <= 3000 | sort by TimeGenerated desc\r\n// Oql: Type=Event EventLog="Operations Manager" EventID:[2000..3000] // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_EventsWithStartedinEventID 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|EventsWithStartedinEventID'
  properties: {
    category: 'Log Management'
    displayName: 'Count of Events containing the word "started" grouped by EventID'
    version: 2
    query: 'search in (Event) "started" | summarize AggregatedValue = count() by EventID\r\n// Oql: Type=Event "started" | Measure count() by EventID // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_FindMaximumTimeTakenForEachPage 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|FindMaximumTimeTakenForEachPage'
  properties: {
    category: 'Log Management'
    displayName: 'Find the maximum time taken for each page'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = max(TimeTaken) by csUriStem\r\n// Oql: Type=W3CIISLog | Measure Max(TimeTaken) by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_IISLogEntriesForClientIP 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|IISLogEntriesForClientIP'
  properties: {
    category: 'Log Management'
    displayName: 'IIS Log Entries for a specific client IP Address (replace with your own)'
    version: 2
    query: 'search cIP == "192.168.0.1" | extend Type = $table | where Type == W3CIISLog | sort by TimeGenerated desc | project csUriStem, scBytes, csBytes, TimeTaken, scStatus\r\n// Oql: Type=W3CIISLog cIP="192.168.0.1" | Select csUriStem,scBytes,csBytes,TimeTaken,scStatus // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_ListAllIISLogEntries 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|ListAllIISLogEntries'
  properties: {
    category: 'Log Management'
    displayName: 'All IIS Log Entries'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | sort by TimeGenerated desc\r\n// Oql: Type=W3CIISLog // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_NoOfConnectionsToOMSDKService 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|NoOfConnectionsToOMSDKService'
  properties: {
    category: 'Log Management'
    displayName: 'How many connections to Operations Manager\'s SDK service by day'
    version: 2
    query: 'Event | where EventID == 26328 and EventLog == "Operations Manager" | summarize AggregatedValue = count() by bin(TimeGenerated, 1d) | sort by TimeGenerated desc\r\n// Oql: Type=Event EventID=26328 EventLog="Operations Manager" | Measure count() interval 1DAY // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_ServerRestartTime 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|ServerRestartTime'
  properties: {
    category: 'Log Management'
    displayName: 'When did my servers initiate restart?'
    version: 2
    query: 'search in (Event) "shutdown" and EventLog == "System" and Source == "User32" and EventID == 1074 | sort by TimeGenerated desc | project TimeGenerated, Computer\r\n// Oql: shutdown Type=Event EventLog=System Source=User32 EventID=1074 | Select TimeGenerated,Computer // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_Show404PagesList 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|Show404PagesList'
  properties: {
    category: 'Log Management'
    displayName: 'Shows which pages people are getting a 404 for'
    version: 2
    query: 'search scStatus == 404 | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by csUriStem\r\n// Oql: Type=W3CIISLog scStatus=404 | Measure count() by csUriStem // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_ShowServersThrowingInternalServerError 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|ShowServersThrowingInternalServerError'
  properties: {
    category: 'Log Management'
    displayName: 'Shows servers that are throwing internal server error'
    version: 2
    query: 'search scStatus == 500 | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = count() by sComputerName\r\n// Oql: Type=W3CIISLog scStatus=500 | Measure count() by sComputerName // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_TotalBytesReceivedByEachAzureRoleInstance 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|TotalBytesReceivedByEachAzureRoleInstance'
  properties: {
    category: 'Log Management'
    displayName: 'Total Bytes received by each Azure Role Instance'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(csBytes) by RoleInstance\r\n// Oql: Type=W3CIISLog | Measure Sum(csBytes) by RoleInstance // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_TotalBytesReceivedByEachIISComputer 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|TotalBytesReceivedByEachIISComputer'
  properties: {
    category: 'Log Management'
    displayName: 'Total Bytes received by each IIS Computer'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(csBytes) by Computer | limit 500000\r\n// Oql: Type=W3CIISLog | Measure Sum(csBytes) by Computer | top 500000 // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_TotalBytesRespondedToClientsByClientIPAddress 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|TotalBytesRespondedToClientsByClientIPAddress'
  properties: {
    category: 'Log Management'
    displayName: 'Total Bytes responded back to clients by Client IP Address'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(scBytes) by cIP\r\n// Oql: Type=W3CIISLog | Measure Sum(scBytes) by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_TotalBytesRespondedToClientsByEachIISServerIPAddress 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|TotalBytesRespondedToClientsByEachIISServerIPAddress'
  properties: {
    category: 'Log Management'
    displayName: 'Total Bytes responded back to clients by each IIS ServerIP Address'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(scBytes) by sIP\r\n// Oql: Type=W3CIISLog | Measure Sum(scBytes) by sIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_TotalBytesSentByClientIPAddress 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|TotalBytesSentByClientIPAddress'
  properties: {
    category: 'Log Management'
    displayName: 'Total Bytes sent by Client IP Address'
    version: 2
    query: 'search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue = sum(csBytes) by cIP\r\n// Oql: Type=W3CIISLog | Measure Sum(csBytes) by cIP // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_WarningEvents 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|WarningEvents'
  properties: {
    category: 'Log Management'
    displayName: 'All Events with level "Warning"'
    version: 2
    query: 'Event | where EventLevelName == "warning" | sort by TimeGenerated desc\r\n// Oql: Type=Event EventLevelName=warning // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_WindowsFireawallPolicySettingsChanged 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|WindowsFireawallPolicySettingsChanged'
  properties: {
    category: 'Log Management'
    displayName: 'Windows Firewall Policy settings have changed'
    version: 2
    query: 'Event | where EventLog == "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" and EventID == 2008 | sort by TimeGenerated desc\r\n// Oql: Type=Event EventLog="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" EventID=2008 // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogManagement_WindowsFireawallPolicySettingsChangedByMachines 'Microsoft.OperationalInsights/workspaces/savedSearches@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogManagement(${workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name})_LogManagement|WindowsFireawallPolicySettingsChangedByMachines'
  properties: {
    category: 'Log Management'
    displayName: 'On which machines and how many times have Windows Firewall Policy settings changed'
    version: 2
    query: 'Event | where EventLog == "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" and EventID == 2008 | summarize AggregatedValue = count() by Computer | limit 500000\r\n// Oql: Type=Event EventLog="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" EventID=2008 | measure count() by Computer | top 500000 // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122'
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AACAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AACAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AACAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AACHttpRequest 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AACHttpRequest'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AACHttpRequest'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADB2CRequestLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADB2CRequestLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADB2CRequestLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADCustomSecurityAttributeAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADCustomSecurityAttributeAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADCustomSecurityAttributeAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesAccountLogon 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesAccountLogon'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesAccountLogon'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesAccountManagement 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesAccountManagement'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesAccountManagement'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesDirectoryServiceAccess 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesDirectoryServiceAccess'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesDirectoryServiceAccess'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesDNSAuditsDynamicUpdates 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesDNSAuditsDynamicUpdates'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesDNSAuditsDynamicUpdates'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesDNSAuditsGeneral 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesDNSAuditsGeneral'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesDNSAuditsGeneral'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesLogonLogoff 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesLogonLogoff'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesLogonLogoff'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesPolicyChange 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesPolicyChange'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesPolicyChange'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesPrivilegeUse 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesPrivilegeUse'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesPrivilegeUse'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADDomainServicesSystemSecurity 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADDomainServicesSystemSecurity'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADDomainServicesSystemSecurity'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADManagedIdentitySignInLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADManagedIdentitySignInLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADManagedIdentitySignInLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADNonInteractiveUserSignInLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADNonInteractiveUserSignInLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADNonInteractiveUserSignInLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADProvisioningLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADProvisioningLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADProvisioningLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADRiskyServicePrincipals 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADRiskyServicePrincipals'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADRiskyServicePrincipals'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADRiskyUsers 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADRiskyUsers'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADRiskyUsers'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADServicePrincipalRiskEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADServicePrincipalRiskEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADServicePrincipalRiskEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADServicePrincipalSignInLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADServicePrincipalSignInLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADServicePrincipalSignInLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AADUserRiskEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AADUserRiskEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AADUserRiskEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ABSBotRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ABSBotRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ABSBotRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ABSChannelToBotRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ABSChannelToBotRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ABSChannelToBotRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ABSDependenciesRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ABSDependenciesRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ABSDependenciesRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACICollaborationAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACICollaborationAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACICollaborationAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACRConnectedClientList 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACRConnectedClientList'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACRConnectedClientList'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACREntraAuthenticationAuditLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACREntraAuthenticationAuditLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACREntraAuthenticationAuditLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSAdvancedMessagingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSAdvancedMessagingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSAdvancedMessagingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSAuthIncomingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSAuthIncomingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSAuthIncomingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSBillingUsage 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSBillingUsage'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSBillingUsage'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallAutomationIncomingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallAutomationIncomingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallAutomationIncomingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallAutomationMediaSummary 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallAutomationMediaSummary'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallAutomationMediaSummary'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallClientMediaStatsTimeSeries 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallClientMediaStatsTimeSeries'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallClientMediaStatsTimeSeries'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallClientOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallClientOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallClientOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallClosedCaptionsSummary 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallClosedCaptionsSummary'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallClosedCaptionsSummary'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallDiagnostics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallDiagnostics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallDiagnostics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallDiagnosticsUpdates 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallDiagnosticsUpdates'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallDiagnosticsUpdates'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallingMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallingMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallingMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallRecordingIncomingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallRecordingIncomingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallRecordingIncomingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallRecordingSummary 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallRecordingSummary'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallRecordingSummary'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallSummary 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallSummary'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallSummary'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallSummaryUpdates 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallSummaryUpdates'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallSummaryUpdates'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSCallSurvey 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSCallSurvey'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSCallSurvey'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSChatIncomingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSChatIncomingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSChatIncomingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSEmailSendMailOperational 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSEmailSendMailOperational'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSEmailSendMailOperational'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSEmailStatusUpdateOperational 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSEmailStatusUpdateOperational'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSEmailStatusUpdateOperational'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSEmailUserEngagementOperational 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSEmailUserEngagementOperational'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSEmailUserEngagementOperational'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSJobRouterIncomingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSJobRouterIncomingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSJobRouterIncomingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSRoomsIncomingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSRoomsIncomingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSRoomsIncomingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ACSSMSIncomingOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ACSSMSIncomingOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ACSSMSIncomingOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AddonAzureBackupAlerts 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AddonAzureBackupAlerts'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AddonAzureBackupAlerts'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AddonAzureBackupJobs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AddonAzureBackupJobs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AddonAzureBackupJobs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AddonAzureBackupPolicy 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AddonAzureBackupPolicy'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AddonAzureBackupPolicy'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AddonAzureBackupProtectedInstance 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AddonAzureBackupProtectedInstance'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AddonAzureBackupProtectedInstance'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AddonAzureBackupStorage 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AddonAzureBackupStorage'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AddonAzureBackupStorage'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFActivityRun 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFActivityRun'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFActivityRun'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFAirflowSchedulerLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFAirflowSchedulerLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFAirflowSchedulerLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFAirflowTaskLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFAirflowTaskLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFAirflowTaskLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFAirflowWebLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFAirflowWebLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFAirflowWebLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFAirflowWorkerLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFAirflowWorkerLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFAirflowWorkerLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFPipelineRun 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFPipelineRun'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFPipelineRun'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSandboxActivityRun 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSandboxActivityRun'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSandboxActivityRun'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSandboxPipelineRun 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSandboxPipelineRun'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSandboxPipelineRun'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSSignInLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSSignInLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSSignInLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSSISIntegrationRuntimeLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSSISIntegrationRuntimeLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSSISIntegrationRuntimeLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSSISPackageEventMessageContext 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSSISPackageEventMessageContext'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSSISPackageEventMessageContext'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSSISPackageEventMessages 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSSISPackageEventMessages'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSSISPackageEventMessages'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSSISPackageExecutableStatistics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSSISPackageExecutableStatistics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSSISPackageExecutableStatistics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSSISPackageExecutionComponentPhases 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSSISPackageExecutionComponentPhases'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSSISPackageExecutionComponentPhases'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFSSISPackageExecutionDataStatistics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFSSISPackageExecutionDataStatistics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFSSISPackageExecutionDataStatistics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADFTriggerRun 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADFTriggerRun'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADFTriggerRun'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADReplicationResult 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADReplicationResult'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADReplicationResult'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADSecurityAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADSecurityAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADSecurityAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADTDataHistoryOperation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADTDataHistoryOperation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADTDataHistoryOperation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADTDigitalTwinsOperation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADTDigitalTwinsOperation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADTDigitalTwinsOperation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADTEventRoutesOperation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADTEventRoutesOperation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADTEventRoutesOperation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADTModelsOperation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADTModelsOperation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADTModelsOperation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADTQueryOperation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADTQueryOperation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADTQueryOperation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADXCommand 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADXCommand'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADXCommand'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADXDataOperation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADXDataOperation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADXDataOperation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADXIngestionBatching 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADXIngestionBatching'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADXIngestionBatching'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADXJournal 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADXJournal'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADXJournal'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADXQuery 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADXQuery'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADXQuery'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADXTableDetails 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADXTableDetails'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADXTableDetails'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ADXTableUsageStatistics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ADXTableUsageStatistics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ADXTableUsageStatistics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AegDataPlaneRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AegDataPlaneRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AegDataPlaneRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AegDeliveryFailureLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AegDeliveryFailureLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AegDeliveryFailureLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AegPublishFailureLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AegPublishFailureLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AegPublishFailureLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AEWAssignmentBlobLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AEWAssignmentBlobLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AEWAssignmentBlobLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AEWAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AEWAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AEWAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AEWComputePipelinesLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AEWComputePipelinesLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AEWComputePipelinesLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AEWExperimentAssignmentSummary 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AEWExperimentAssignmentSummary'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AEWExperimentAssignmentSummary'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AEWExperimentScorecardMetricPairs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AEWExperimentScorecardMetricPairs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AEWExperimentScorecardMetricPairs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AEWExperimentScorecards 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AEWExperimentScorecards'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AEWExperimentScorecards'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AFSAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AFSAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AFSAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AGCAccessLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AGCAccessLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AGCAccessLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodApplicationAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodApplicationAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodApplicationAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodFarmManagementLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodFarmManagementLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodFarmManagementLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodFarmOperationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodFarmOperationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodFarmOperationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodInsightLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodInsightLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodInsightLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodJobProcessedLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodJobProcessedLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodJobProcessedLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodModelInferenceLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodModelInferenceLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodModelInferenceLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodProviderAuthLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodProviderAuthLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodProviderAuthLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodSatelliteLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodSatelliteLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodSatelliteLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodSensorManagementLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodSensorManagementLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodSensorManagementLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AgriFoodWeatherLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AgriFoodWeatherLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AgriFoodWeatherLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AGSGrafanaLoginEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AGSGrafanaLoginEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AGSGrafanaLoginEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AGSGrafanaUsageInsightsEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AGSGrafanaUsageInsightsEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AGSGrafanaUsageInsightsEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AGWAccessLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AGWAccessLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AGWAccessLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AGWFirewallLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AGWFirewallLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AGWFirewallLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AGWPerformanceLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AGWPerformanceLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AGWPerformanceLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AHDSDeidAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AHDSDeidAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AHDSDeidAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AHDSDicomAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AHDSDicomAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AHDSDicomAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AHDSDicomDiagnosticLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AHDSDicomDiagnosticLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AHDSDicomDiagnosticLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AHDSMedTechDiagnosticLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AHDSMedTechDiagnosticLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AHDSMedTechDiagnosticLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AirflowDagProcessingLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AirflowDagProcessingLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AirflowDagProcessingLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AKSAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AKSAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AKSAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AKSAuditAdmin 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AKSAuditAdmin'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AKSAuditAdmin'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AKSControlPlane 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AKSControlPlane'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AKSControlPlane'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ALBHealthEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ALBHealthEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ALBHealthEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Alert 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Alert'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'Alert'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlComputeClusterEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlComputeClusterEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlComputeClusterEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlComputeClusterNodeEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlComputeClusterNodeEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlComputeClusterNodeEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlComputeCpuGpuUtilization 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlComputeCpuGpuUtilization'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlComputeCpuGpuUtilization'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlComputeInstanceEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlComputeInstanceEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlComputeInstanceEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlComputeJobEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlComputeJobEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlComputeJobEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlDataLabelEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlDataLabelEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlDataLabelEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlDataSetEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlDataSetEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlDataSetEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlDataStoreEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlDataStoreEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlDataStoreEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlDeploymentEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlDeploymentEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlDeploymentEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlEnvironmentEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlEnvironmentEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlEnvironmentEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlInferencingEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlInferencingEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlInferencingEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlModelsEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlModelsEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlModelsEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlOnlineEndpointConsoleLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlOnlineEndpointConsoleLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlOnlineEndpointConsoleLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlOnlineEndpointEventLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlOnlineEndpointEventLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlOnlineEndpointEventLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlOnlineEndpointTrafficLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlOnlineEndpointTrafficLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlOnlineEndpointTrafficLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlPipelineEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlPipelineEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlPipelineEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlRegistryReadEventsLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlRegistryReadEventsLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlRegistryReadEventsLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlRegistryWriteEventsLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlRegistryWriteEventsLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlRegistryWriteEventsLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlRunEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlRunEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlRunEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AmlRunStatusChangedEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AmlRunStatusChangedEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AmlRunStatusChangedEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AMSKeyDeliveryRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AMSKeyDeliveryRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AMSKeyDeliveryRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AMSLiveEventOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AMSLiveEventOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AMSLiveEventOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AMSMediaAccountHealth 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AMSMediaAccountHealth'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AMSMediaAccountHealth'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AMSStreamingEndpointRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AMSStreamingEndpointRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AMSStreamingEndpointRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AMWMetricsUsageDetails 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AMWMetricsUsageDetails'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AMWMetricsUsageDetails'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ANFFileAccess 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ANFFileAccess'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ANFFileAccess'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AOIDatabaseQuery 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AOIDatabaseQuery'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AOIDatabaseQuery'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AOIDigestion 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AOIDigestion'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AOIDigestion'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AOIStorage 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AOIStorage'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AOIStorage'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ApiManagementGatewayLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ApiManagementGatewayLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ApiManagementGatewayLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ApiManagementWebSocketConnectionLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ApiManagementWebSocketConnectionLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ApiManagementWebSocketConnectionLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_APIMDevPortalAuditDiagnosticLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'APIMDevPortalAuditDiagnosticLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'APIMDevPortalAuditDiagnosticLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppAvailabilityResults 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppAvailabilityResults'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppAvailabilityResults'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppBrowserTimings 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppBrowserTimings'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppBrowserTimings'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppCenterError 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppCenterError'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppCenterError'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppDependencies 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppDependencies'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppDependencies'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppEnvSpringAppConsoleLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppEnvSpringAppConsoleLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppEnvSpringAppConsoleLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppEvents'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppEvents'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppExceptions 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppExceptions'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppExceptions'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppMetrics'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppMetrics'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppPageViews 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppPageViews'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppPageViews'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppPerformanceCounters 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppPerformanceCounters'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppPerformanceCounters'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppPlatformBuildLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppPlatformBuildLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppPlatformBuildLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppPlatformContainerEventLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppPlatformContainerEventLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppPlatformContainerEventLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppPlatformIngressLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppPlatformIngressLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppPlatformIngressLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppPlatformLogsforSpring 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppPlatformLogsforSpring'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppPlatformLogsforSpring'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppPlatformSystemLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppPlatformSystemLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppPlatformSystemLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppRequests'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppRequests'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceAntivirusScanAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceAntivirusScanAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceAntivirusScanAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceAppLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceAppLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceAppLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceAuthenticationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceAuthenticationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceAuthenticationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceConsoleLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceConsoleLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceConsoleLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceEnvironmentPlatformLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceEnvironmentPlatformLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceEnvironmentPlatformLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceFileAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceFileAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceFileAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceHTTPLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceHTTPLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceHTTPLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceIPSecAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceIPSecAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceIPSecAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServicePlatformLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServicePlatformLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServicePlatformLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppServiceServerlessSecurityPluginData 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppServiceServerlessSecurityPluginData'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AppServiceServerlessSecurityPluginData'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppSystemEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppSystemEvents'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppSystemEvents'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AppTraces 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AppTraces'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AppTraces'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ArcK8sAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ArcK8sAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ArcK8sAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ArcK8sAuditAdmin 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ArcK8sAuditAdmin'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ArcK8sAuditAdmin'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ArcK8sControlPlane 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ArcK8sControlPlane'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ArcK8sControlPlane'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ASCAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ASCAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ASCAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ASCDeviceEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ASCDeviceEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ASCDeviceEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ASRJobs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ASRJobs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ASRJobs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ASRReplicatedItems 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ASRReplicatedItems'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ASRReplicatedItems'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ATCExpressRouteCircuitIpfix 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ATCExpressRouteCircuitIpfix'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ATCExpressRouteCircuitIpfix'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ATCMicrosoftPeeringMetadata 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ATCMicrosoftPeeringMetadata'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ATCMicrosoftPeeringMetadata'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ATCPrivatePeeringMetadata 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ATCPrivatePeeringMetadata'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ATCPrivatePeeringMetadata'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AUIEventsAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AUIEventsAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AUIEventsAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AUIEventsOperational 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AUIEventsOperational'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AUIEventsOperational'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AutoscaleEvaluationsLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AutoscaleEvaluationsLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AutoscaleEvaluationsLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AutoscaleScaleActionsLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AutoscaleScaleActionsLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AutoscaleScaleActionsLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AVNMConnectivityConfigurationChange 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AVNMConnectivityConfigurationChange'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AVNMConnectivityConfigurationChange'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AVNMIPAMPoolAllocationChange 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AVNMIPAMPoolAllocationChange'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AVNMIPAMPoolAllocationChange'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AVNMNetworkGroupMembershipChange 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AVNMNetworkGroupMembershipChange'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AVNMNetworkGroupMembershipChange'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AVNMRuleCollectionChange 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AVNMRuleCollectionChange'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AVNMRuleCollectionChange'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AVSSyslog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AVSSyslog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AVSSyslog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWApplicationRule 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWApplicationRule'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWApplicationRule'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWApplicationRuleAggregation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWApplicationRuleAggregation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWApplicationRuleAggregation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWDnsQuery 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWDnsQuery'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWDnsQuery'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWFatFlow 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWFatFlow'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWFatFlow'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWFlowTrace 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWFlowTrace'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWFlowTrace'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWIdpsSignature 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWIdpsSignature'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWIdpsSignature'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWInternalFqdnResolutionFailure 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWInternalFqdnResolutionFailure'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWInternalFqdnResolutionFailure'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWNatRule 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWNatRule'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWNatRule'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWNatRuleAggregation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWNatRuleAggregation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWNatRuleAggregation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWNetworkRule 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWNetworkRule'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWNetworkRule'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWNetworkRuleAggregation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWNetworkRuleAggregation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWNetworkRuleAggregation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZFWThreatIntel 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZFWThreatIntel'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZFWThreatIntel'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZKVAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZKVAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZKVAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZKVPolicyEvaluationDetailsLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZKVPolicyEvaluationDetailsLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZKVPolicyEvaluationDetailsLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSApplicationMetricLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSApplicationMetricLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSApplicationMetricLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSArchiveLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSArchiveLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSArchiveLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSAutoscaleLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSAutoscaleLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSAutoscaleLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSCustomerManagedKeyUserLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSCustomerManagedKeyUserLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSCustomerManagedKeyUserLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSDiagnosticErrorLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSDiagnosticErrorLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSDiagnosticErrorLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSHybridConnectionsEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSHybridConnectionsEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSHybridConnectionsEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSKafkaCoordinatorLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSKafkaCoordinatorLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSKafkaCoordinatorLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSKafkaUserErrorLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSKafkaUserErrorLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSKafkaUserErrorLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSOperationalLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSOperationalLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSOperationalLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSRunTimeAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSRunTimeAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSRunTimeAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AZMSVnetConnectionEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AZMSVnetConnectionEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AZMSVnetConnectionEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureActivity 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureActivity'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'AzureActivity'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureActivityV2 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureActivityV2'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureActivityV2'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureAttestationDiagnostics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureAttestationDiagnostics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureAttestationDiagnostics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureBackupOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureBackupOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureBackupOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureCloudHsmAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureCloudHsmAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureCloudHsmAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureDevOpsAuditing 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureDevOpsAuditing'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureDevOpsAuditing'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureLoadTestingOperation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureLoadTestingOperation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureLoadTestingOperation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_AzureMetricsV2 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'AzureMetricsV2'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'AzureMetricsV2'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_BaiClusterEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'BaiClusterEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'BaiClusterEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_BaiJobEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'BaiJobEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'BaiJobEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_BlockchainApplicationLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'BlockchainApplicationLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'BlockchainApplicationLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_BlockchainProxyLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'BlockchainProxyLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'BlockchainProxyLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CassandraAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CassandraAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CassandraAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CassandraLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CassandraLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CassandraLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CCFApplicationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CCFApplicationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CCFApplicationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBCassandraRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBCassandraRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBCassandraRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBControlPlaneRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBControlPlaneRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBControlPlaneRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBDataPlaneRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBDataPlaneRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBDataPlaneRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBGremlinRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBGremlinRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBGremlinRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBMongoRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBMongoRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBMongoRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBPartitionKeyRUConsumption 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBPartitionKeyRUConsumption'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBPartitionKeyRUConsumption'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBPartitionKeyStatistics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBPartitionKeyStatistics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBPartitionKeyStatistics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBQueryRuntimeStatistics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBQueryRuntimeStatistics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBQueryRuntimeStatistics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CDBTableApiRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CDBTableApiRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CDBTableApiRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ChaosStudioExperimentEventLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ChaosStudioExperimentEventLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ChaosStudioExperimentEventLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CHSMManagementAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CHSMManagementAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CHSMManagementAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CHSMServiceOperationAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CHSMServiceOperationAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CHSMServiceOperationAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CIEventsAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CIEventsAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CIEventsAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CIEventsOperational 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CIEventsOperational'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CIEventsOperational'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CloudHsmServiceOperationAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CloudHsmServiceOperationAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CloudHsmServiceOperationAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ComputerGroup 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ComputerGroup'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ComputerGroup'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerAppConsoleLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerAppConsoleLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerAppConsoleLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerAppSystemLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerAppSystemLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerAppSystemLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerImageInventory 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerImageInventory'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerImageInventory'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerInstanceLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerInstanceLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerInstanceLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerInventory 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerInventory'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerInventory'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerLogV2 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerLogV2'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerLogV2'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerNodeInventory 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerNodeInventory'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerNodeInventory'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerRegistryLoginEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerRegistryLoginEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerRegistryLoginEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerRegistryRepositoryEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerRegistryRepositoryEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerRegistryRepositoryEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ContainerServiceLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ContainerServiceLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ContainerServiceLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_CoreAzureBackup 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'CoreAzureBackup'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'CoreAzureBackup'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksAccounts 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksAccounts'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksAccounts'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksApps 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksApps'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksApps'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksBrickStoreHttpGateway 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksBrickStoreHttpGateway'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksBrickStoreHttpGateway'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksBudgetPolicyCentral 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksBudgetPolicyCentral'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksBudgetPolicyCentral'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksCapsule8Dataplane 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksCapsule8Dataplane'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksCapsule8Dataplane'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksClamAVScan 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksClamAVScan'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksClamAVScan'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksCloudStorageMetadata 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksCloudStorageMetadata'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksCloudStorageMetadata'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksClusterLibraries 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksClusterLibraries'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksClusterLibraries'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksClusterPolicies 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksClusterPolicies'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksClusterPolicies'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksClusters 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksClusters'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksClusters'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksDashboards 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksDashboards'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksDashboards'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksDatabricksSQL 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksDatabricksSQL'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksDatabricksSQL'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksDataMonitoring 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksDataMonitoring'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksDataMonitoring'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksDataRooms 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksDataRooms'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksDataRooms'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksDBFS 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksDBFS'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksDBFS'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksDeltaPipelines 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksDeltaPipelines'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksDeltaPipelines'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksFeatureStore 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksFeatureStore'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksFeatureStore'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksFiles 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksFiles'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksFiles'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksFilesystem 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksFilesystem'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksFilesystem'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksGenie 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksGenie'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksGenie'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksGitCredentials 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksGitCredentials'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksGitCredentials'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksGlobalInitScripts 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksGlobalInitScripts'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksGlobalInitScripts'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksGroups 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksGroups'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksGroups'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksIAMRole 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksIAMRole'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksIAMRole'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksIngestion 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksIngestion'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksIngestion'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksInstancePools 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksInstancePools'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksInstancePools'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksJobs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksJobs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksJobs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksLakeviewConfig 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksLakeviewConfig'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksLakeviewConfig'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksLineageTracking 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksLineageTracking'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksLineageTracking'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksMarketplaceConsumer 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksMarketplaceConsumer'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksMarketplaceConsumer'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksMarketplaceProvider 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksMarketplaceProvider'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksMarketplaceProvider'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksMLflowAcledArtifact 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksMLflowAcledArtifact'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksMLflowAcledArtifact'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksMLflowExperiment 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksMLflowExperiment'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksMLflowExperiment'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksModelRegistry 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksModelRegistry'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksModelRegistry'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksNotebook 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksNotebook'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksNotebook'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksOnlineTables 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksOnlineTables'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksOnlineTables'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksPartnerHub 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksPartnerHub'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksPartnerHub'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksPredictiveOptimization 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksPredictiveOptimization'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksPredictiveOptimization'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksRBAC 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksRBAC'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksRBAC'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksRemoteHistoryService 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksRemoteHistoryService'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksRemoteHistoryService'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksRepos 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksRepos'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksRepos'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksRFA 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksRFA'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksRFA'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksSecrets 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksSecrets'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksSecrets'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksServerlessRealTimeInference 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksServerlessRealTimeInference'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksServerlessRealTimeInference'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksSQL 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksSQL'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksSQL'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksSQLPermissions 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksSQLPermissions'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksSQLPermissions'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksSSH 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksSSH'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksSSH'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksTables 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksTables'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksTables'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksUnityCatalog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksUnityCatalog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksUnityCatalog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksVectorSearch 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksVectorSearch'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksVectorSearch'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksWebhookNotifications 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksWebhookNotifications'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksWebhookNotifications'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksWebTerminal 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksWebTerminal'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksWebTerminal'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksWorkspace 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksWorkspace'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksWorkspace'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DatabricksWorkspaceFiles 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DatabricksWorkspaceFiles'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DatabricksWorkspaceFiles'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DataTransferOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DataTransferOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DataTransferOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DCRLogErrors 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DCRLogErrors'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DCRLogErrors'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DCRLogTroubleshooting 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DCRLogTroubleshooting'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DCRLogTroubleshooting'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DevCenterBillingEventLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DevCenterBillingEventLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DevCenterBillingEventLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DevCenterDiagnosticLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DevCenterDiagnosticLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DevCenterDiagnosticLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DevCenterResourceOperationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DevCenterResourceOperationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DevCenterResourceOperationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DNSQueryLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DNSQueryLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DNSQueryLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DSMAzureBlobStorageLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DSMAzureBlobStorageLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DSMAzureBlobStorageLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DSMDataClassificationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DSMDataClassificationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DSMDataClassificationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_DSMDataLabelingLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'DSMDataLabelingLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'DSMDataLabelingLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EGNFailedHttpDataPlaneOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EGNFailedHttpDataPlaneOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EGNFailedHttpDataPlaneOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EGNFailedMqttConnections 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EGNFailedMqttConnections'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EGNFailedMqttConnections'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EGNFailedMqttPublishedMessages 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EGNFailedMqttPublishedMessages'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EGNFailedMqttPublishedMessages'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EGNFailedMqttSubscriptions 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EGNFailedMqttSubscriptions'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EGNFailedMqttSubscriptions'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EGNMqttDisconnections 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EGNMqttDisconnections'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EGNMqttDisconnections'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EGNSuccessfulHttpDataPlaneOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EGNSuccessfulHttpDataPlaneOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EGNSuccessfulHttpDataPlaneOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EGNSuccessfulMqttConnections 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EGNSuccessfulMqttConnections'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EGNSuccessfulMqttConnections'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_EnrichedMicrosoft365AuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'EnrichedMicrosoft365AuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'EnrichedMicrosoft365AuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ETWEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ETWEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ETWEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Event 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Event'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'Event'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ExchangeAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ExchangeAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ExchangeAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ExchangeOnlineAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ExchangeOnlineAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ExchangeOnlineAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_FailedIngestion 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'FailedIngestion'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'FailedIngestion'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_FunctionAppLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'FunctionAppLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'FunctionAppLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightAmbariClusterAlerts 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightAmbariClusterAlerts'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightAmbariClusterAlerts'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightAmbariSystemMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightAmbariSystemMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightAmbariSystemMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightGatewayAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightGatewayAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightGatewayAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHadoopAndYarnLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHadoopAndYarnLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHadoopAndYarnLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHadoopAndYarnMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHadoopAndYarnMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHadoopAndYarnMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHBaseLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHBaseLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHBaseLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHBaseMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHBaseMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHBaseMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHiveAndLLAPLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHiveAndLLAPLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHiveAndLLAPLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHiveAndLLAPMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHiveAndLLAPMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHiveAndLLAPMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHiveQueryAppStats 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHiveQueryAppStats'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHiveQueryAppStats'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightHiveTezAppStats 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightHiveTezAppStats'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightHiveTezAppStats'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightJupyterNotebookEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightJupyterNotebookEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightJupyterNotebookEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightKafkaLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightKafkaLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightKafkaLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightKafkaMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightKafkaMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightKafkaMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightKafkaServerLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightKafkaServerLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightKafkaServerLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightOozieLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightOozieLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightOozieLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightRangerAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightRangerAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightRangerAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSecurityLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSecurityLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSecurityLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkApplicationEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkApplicationEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkApplicationEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkBlockManagerEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkBlockManagerEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkBlockManagerEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkEnvironmentEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkEnvironmentEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkEnvironmentEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkExecutorEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkExecutorEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkExecutorEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkExtraEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkExtraEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkExtraEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkJobEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkJobEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkJobEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkSQLExecutionEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkSQLExecutionEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkSQLExecutionEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkStageEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkStageEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkStageEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkStageTaskAccumulables 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkStageTaskAccumulables'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkStageTaskAccumulables'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightSparkTaskEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightSparkTaskEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightSparkTaskEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightStormLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightStormLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightStormLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightStormMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightStormMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightStormMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HDInsightStormTopologyMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HDInsightStormTopologyMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HDInsightStormTopologyMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_HealthStateChangeEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'HealthStateChangeEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'HealthStateChangeEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Heartbeat 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Heartbeat'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'Heartbeat'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_InsightsMetrics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'InsightsMetrics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'InsightsMetrics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_IntuneAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'IntuneAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'IntuneAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_IntuneDeviceComplianceOrg 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'IntuneDeviceComplianceOrg'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'IntuneDeviceComplianceOrg'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_IntuneDevices 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'IntuneDevices'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'IntuneDevices'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_IntuneOperationalLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'IntuneOperationalLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'IntuneOperationalLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_KubeEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'KubeEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'KubeEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_KubeHealth 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'KubeHealth'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'KubeHealth'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_KubeMonAgentEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'KubeMonAgentEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'KubeMonAgentEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_KubeNodeInventory 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'KubeNodeInventory'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'KubeNodeInventory'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_KubePodInventory 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'KubePodInventory'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'KubePodInventory'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_KubePVInventory 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'KubePVInventory'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'KubePVInventory'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_KubeServices 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'KubeServices'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'KubeServices'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LAQueryLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LAQueryLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'LAQueryLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LASummaryLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LASummaryLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'LASummaryLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_LogicAppWorkflowRuntime 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'LogicAppWorkflowRuntime'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'LogicAppWorkflowRuntime'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MCCEventLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MCCEventLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MCCEventLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MCVPAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MCVPAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MCVPAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MCVPOperationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MCVPOperationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MCVPOperationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MDCDetectionDNSEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MDCDetectionDNSEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MDCDetectionDNSEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MDCDetectionFimEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MDCDetectionFimEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MDCDetectionFimEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MDCDetectionGatingValidationEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MDCDetectionGatingValidationEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MDCDetectionGatingValidationEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MDCFileIntegrityMonitoringEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MDCFileIntegrityMonitoringEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MDCFileIntegrityMonitoringEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MDECustomCollectionDeviceFileEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MDECustomCollectionDeviceFileEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MDECustomCollectionDeviceFileEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftAzureBastionAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftAzureBastionAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftAzureBastionAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftDataShareReceivedSnapshotLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftDataShareReceivedSnapshotLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftDataShareReceivedSnapshotLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftDataShareSentSnapshotLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftDataShareSentSnapshotLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftDataShareSentSnapshotLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftDataShareShareLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftDataShareShareLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftDataShareShareLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftDynamicsTelemetryPerformanceLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftDynamicsTelemetryPerformanceLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftDynamicsTelemetryPerformanceLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftDynamicsTelemetrySystemMetricsLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftDynamicsTelemetrySystemMetricsLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftDynamicsTelemetrySystemMetricsLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftGraphActivityLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftGraphActivityLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftGraphActivityLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MicrosoftHealthcareApisAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MicrosoftHealthcareApisAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MicrosoftHealthcareApisAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MNFDeviceUpdates 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MNFDeviceUpdates'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MNFDeviceUpdates'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MNFSystemSessionHistoryUpdates 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MNFSystemSessionHistoryUpdates'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MNFSystemSessionHistoryUpdates'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_MNFSystemStateMessageUpdates 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'MNFSystemStateMessageUpdates'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'MNFSystemStateMessageUpdates'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NatGatewayFlowlogsV1 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NatGatewayFlowlogsV1'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NatGatewayFlowlogsV1'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCBMBreakGlassAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCBMBreakGlassAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCBMBreakGlassAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCBMSecurityDefenderLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCBMSecurityDefenderLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCBMSecurityDefenderLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCBMSecurityLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCBMSecurityLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCBMSecurityLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCBMSystemLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCBMSystemLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCBMSystemLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCCKubernetesLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCCKubernetesLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCCKubernetesLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCCPlatformOperationsLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCCPlatformOperationsLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCCPlatformOperationsLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCCVMOrchestrationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCCVMOrchestrationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCCVMOrchestrationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCMClusterOperationsLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCMClusterOperationsLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCMClusterOperationsLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCSStorageAlerts 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCSStorageAlerts'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCSStorageAlerts'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCSStorageAudits 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCSStorageAudits'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCSStorageAudits'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NCSStorageLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NCSStorageLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NCSStorageLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NetworkAccessAlerts 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NetworkAccessAlerts'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NetworkAccessAlerts'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NetworkAccessConnectionEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NetworkAccessConnectionEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NetworkAccessConnectionEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NetworkAccessTraffic 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NetworkAccessTraffic'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NetworkAccessTraffic'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NginxUpstreamUpdateLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NginxUpstreamUpdateLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NginxUpstreamUpdateLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NGXOperationLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NGXOperationLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NGXOperationLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NGXSecurityLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NGXSecurityLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NGXSecurityLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NSPAccessLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NSPAccessLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NSPAccessLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NTAInsights 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NTAInsights'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NTAInsights'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NTAIpDetails 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NTAIpDetails'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NTAIpDetails'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NTANetAnalytics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NTANetAnalytics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NTANetAnalytics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NTATopologyDetails 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NTATopologyDetails'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NTATopologyDetails'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NWConnectionMonitorDestinationListenerResult 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NWConnectionMonitorDestinationListenerResult'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NWConnectionMonitorDestinationListenerResult'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NWConnectionMonitorDNSResult 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NWConnectionMonitorDNSResult'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NWConnectionMonitorDNSResult'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NWConnectionMonitorPathResult 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NWConnectionMonitorPathResult'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NWConnectionMonitorPathResult'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_NWConnectionMonitorTestResult 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'NWConnectionMonitorTestResult'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'NWConnectionMonitorTestResult'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEPAirFlowTask 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEPAirFlowTask'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEPAirFlowTask'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEPAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEPAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEPAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEPDataplaneLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEPDataplaneLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEPDataplaneLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEPElasticOperator 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEPElasticOperator'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEPElasticOperator'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEPElasticsearch 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEPElasticsearch'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEPElasticsearch'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEWExperimentAssignmentSummary 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEWExperimentAssignmentSummary'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEWExperimentAssignmentSummary'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEWExperimentScorecardMetricPairs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEWExperimentScorecardMetricPairs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEWExperimentScorecardMetricPairs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OEWExperimentScorecards 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OEWExperimentScorecards'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OEWExperimentScorecards'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OLPSupplyChainEntityOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OLPSupplyChainEntityOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OLPSupplyChainEntityOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_OLPSupplyChainEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'OLPSupplyChainEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'OLPSupplyChainEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Operation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Operation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'Operation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Perf 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Perf'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'Perf'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PFTitleAuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PFTitleAuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PFTitleAuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PowerBIAuditTenant 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PowerBIAuditTenant'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PowerBIAuditTenant'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PowerBIDatasetsTenant 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PowerBIDatasetsTenant'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PowerBIDatasetsTenant'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PowerBIDatasetsTenantPreview 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PowerBIDatasetsTenantPreview'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PowerBIDatasetsTenantPreview'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PowerBIDatasetsWorkspace 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PowerBIDatasetsWorkspace'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PowerBIDatasetsWorkspace'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PowerBIDatasetsWorkspacePreview 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PowerBIDatasetsWorkspacePreview'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PowerBIDatasetsWorkspacePreview'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PowerBIReportUsageTenant 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PowerBIReportUsageTenant'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PowerBIReportUsageTenant'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PowerBIReportUsageWorkspace 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PowerBIReportUsageWorkspace'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PowerBIReportUsageWorkspace'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PurviewDataSensitivityLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PurviewDataSensitivityLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PurviewDataSensitivityLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PurviewScanStatusLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PurviewScanStatusLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PurviewScanStatusLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_PurviewSecurityLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'PurviewSecurityLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'PurviewSecurityLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_REDConnectionEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'REDConnectionEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'REDConnectionEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_RemoteNetworkHealthLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'RemoteNetworkHealthLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'RemoteNetworkHealthLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ResourceManagementPublicAccessLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ResourceManagementPublicAccessLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ResourceManagementPublicAccessLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SCCMAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SCCMAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SCCMAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SCGPoolExecutionLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SCGPoolExecutionLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SCGPoolExecutionLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SCGPoolRequestLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SCGPoolRequestLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SCGPoolRequestLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SCOMAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SCOMAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SCOMAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ServiceFabricOperationalEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ServiceFabricOperationalEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ServiceFabricOperationalEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ServiceFabricReliableActorEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ServiceFabricReliableActorEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ServiceFabricReliableActorEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_ServiceFabricReliableServiceEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'ServiceFabricReliableServiceEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'ServiceFabricReliableServiceEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SfBAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SfBAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SfBAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SfBOnlineAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SfBOnlineAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SfBOnlineAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SharePointOnlineAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SharePointOnlineAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SharePointOnlineAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SignalRServiceDiagnosticLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SignalRServiceDiagnosticLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SignalRServiceDiagnosticLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SigninLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SigninLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SigninLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SPAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SPAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SPAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SQLAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SQLAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SQLAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SQLSecurityAuditEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SQLSecurityAuditEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SQLSecurityAuditEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageAntimalwareScanResults 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageAntimalwareScanResults'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageAntimalwareScanResults'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageBlobLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageBlobLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageBlobLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageCacheOperationEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageCacheOperationEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageCacheOperationEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageCacheUpgradeEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageCacheUpgradeEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageCacheUpgradeEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageCacheWarningEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageCacheWarningEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageCacheWarningEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageFileLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageFileLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageFileLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageMalwareScanningResults 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageMalwareScanningResults'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageMalwareScanningResults'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageMoverCopyLogsFailed 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageMoverCopyLogsFailed'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageMoverCopyLogsFailed'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageMoverCopyLogsTransferred 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageMoverCopyLogsTransferred'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageMoverCopyLogsTransferred'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageMoverJobRunLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageMoverJobRunLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageMoverJobRunLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageQueueLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageQueueLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageQueueLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_StorageTableLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'StorageTableLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'StorageTableLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SucceededIngestion 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SucceededIngestion'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SucceededIngestion'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SVMPoolExecutionLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SVMPoolExecutionLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SVMPoolExecutionLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SVMPoolRequestLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SVMPoolRequestLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SVMPoolRequestLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseBigDataPoolApplicationsEnded 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseBigDataPoolApplicationsEnded'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseBigDataPoolApplicationsEnded'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseBuiltinSqlPoolRequestsEnded 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseBuiltinSqlPoolRequestsEnded'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseBuiltinSqlPoolRequestsEnded'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseDXCommand 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseDXCommand'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseDXCommand'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseDXFailedIngestion 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseDXFailedIngestion'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseDXFailedIngestion'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseDXIngestionBatching 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseDXIngestionBatching'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseDXIngestionBatching'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseDXQuery 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseDXQuery'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseDXQuery'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseDXSucceededIngestion 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseDXSucceededIngestion'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseDXSucceededIngestion'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseDXTableDetails 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseDXTableDetails'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseDXTableDetails'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseDXTableUsageStatistics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseDXTableUsageStatistics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseDXTableUsageStatistics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseGatewayApiRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseGatewayApiRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseGatewayApiRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseGatewayEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseGatewayEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseGatewayEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseIntegrationActivityRuns 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseIntegrationActivityRuns'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseIntegrationActivityRuns'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseIntegrationActivityRunsEnded 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseIntegrationActivityRunsEnded'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseIntegrationActivityRunsEnded'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseIntegrationPipelineRuns 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseIntegrationPipelineRuns'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseIntegrationPipelineRuns'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseIntegrationPipelineRunsEnded 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseIntegrationPipelineRunsEnded'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseIntegrationPipelineRunsEnded'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseIntegrationTriggerRuns 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseIntegrationTriggerRuns'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseIntegrationTriggerRuns'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseIntegrationTriggerRunsEnded 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseIntegrationTriggerRunsEnded'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseIntegrationTriggerRunsEnded'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseLinkEvent 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseLinkEvent'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseLinkEvent'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseRBACEvents 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseRBACEvents'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseRBACEvents'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseRbacOperations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseRbacOperations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseRbacOperations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseScopePoolScopeJobsEnded 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseScopePoolScopeJobsEnded'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseScopePoolScopeJobsEnded'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseScopePoolScopeJobsStateChange 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseScopePoolScopeJobsStateChange'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseScopePoolScopeJobsStateChange'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseSqlPoolDmsWorkers 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseSqlPoolDmsWorkers'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseSqlPoolDmsWorkers'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseSqlPoolExecRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseSqlPoolExecRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseSqlPoolExecRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseSqlPoolRequestSteps 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseSqlPoolRequestSteps'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseSqlPoolRequestSteps'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseSqlPoolSqlRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseSqlPoolSqlRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseSqlPoolSqlRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_SynapseSqlPoolWaits 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'SynapseSqlPoolWaits'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'SynapseSqlPoolWaits'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Syslog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Syslog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'Syslog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_TOUserAudits 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'TOUserAudits'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'TOUserAudits'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_TOUserDiagnostics 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'TOUserDiagnostics'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'TOUserDiagnostics'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_TSIIngress 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'TSIIngress'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'TSIIngress'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCClient 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCClient'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCClient'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCClientReadinessStatus 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCClientReadinessStatus'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCClientReadinessStatus'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCClientUpdateStatus 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCClientUpdateStatus'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCClientUpdateStatus'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCDeviceAlert 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCDeviceAlert'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCDeviceAlert'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCDOAggregatedStatus 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCDOAggregatedStatus'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCDOAggregatedStatus'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCDOStatus 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCDOStatus'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCDOStatus'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCServiceUpdateStatus 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCServiceUpdateStatus'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCServiceUpdateStatus'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_UCUpdateAlert 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'UCUpdateAlert'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'UCUpdateAlert'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Usage 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Usage'
  properties: {
    totalRetentionInDays: 90
    plan: 'Analytics'
    schema: {
      name: 'Usage'
    }
    retentionInDays: 90
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_VCoreMongoRequests 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'VCoreMongoRequests'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'VCoreMongoRequests'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_VIAudit 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'VIAudit'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'VIAudit'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_VIIndexing 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'VIIndexing'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'VIIndexing'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_VMBoundPort 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'VMBoundPort'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'VMBoundPort'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_VMComputer 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'VMComputer'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'VMComputer'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_VMConnection 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'VMConnection'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'VMConnection'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_VMProcess 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'VMProcess'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'VMProcess'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_W3CIISLog 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'W3CIISLog'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'W3CIISLog'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WebPubSubConnectivity 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WebPubSubConnectivity'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WebPubSubConnectivity'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WebPubSubHttpRequest 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WebPubSubHttpRequest'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WebPubSubHttpRequest'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WebPubSubMessaging 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WebPubSubMessaging'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WebPubSubMessaging'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_Windows365AuditLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'Windows365AuditLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'Windows365AuditLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WindowsClientAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WindowsClientAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WindowsClientAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WindowsServerAssessmentRecommendation 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WindowsServerAssessmentRecommendation'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WindowsServerAssessmentRecommendation'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WorkloadDiagnosticLogs 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WorkloadDiagnosticLogs'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WorkloadDiagnosticLogs'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDAgentHealthStatus 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDAgentHealthStatus'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDAgentHealthStatus'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDAutoscaleEvaluationPooled 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDAutoscaleEvaluationPooled'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDAutoscaleEvaluationPooled'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDCheckpoints 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDCheckpoints'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDCheckpoints'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDConnectionGraphicsDataPreview 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDConnectionGraphicsDataPreview'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDConnectionGraphicsDataPreview'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDConnectionNetworkData 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDConnectionNetworkData'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDConnectionNetworkData'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDConnections 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDConnections'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDConnections'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDErrors 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDErrors'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDErrors'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDFeeds 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDFeeds'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDFeeds'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDHostRegistrations 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDHostRegistrations'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDHostRegistrations'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDManagement 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDManagement'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDManagement'
    }
    retentionInDays: 30
  }
}

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_WVDSessionHostManagement 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource
  name: 'WVDSessionHostManagement'
  properties: {
    totalRetentionInDays: 30
    plan: 'Analytics'
    schema: {
      name: 'WVDSessionHostManagement'
    }
    retentionInDays: 30
  }
}

resource solutions_ContainerInsights_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: solutions_ContainerInsights_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name
  location: 'canadacentral'
  plan: {
    name: 'ContainerInsights(57123c17-af1a-4ec2-9494-a214fb148bf4-rg-genai-accelerator-ccan)'
    promotionCode: ''
    product: 'OMSGallery/ContainerInsights'
    publisher: 'Microsoft'
  }
  properties: {
    workspaceResourceId: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource.id
    containedResources: []
  }
}

resource storageAccounts_genaisadevcc01_name_default 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccounts_genaisadevcc01_name_resource
  name: 'default'
  sku: {
    name: 'Standard_LRS'
    tier: 'Standard'
  }
  properties: {
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    cors: {
      corsRules: []
    }
    deleteRetentionPolicy: {
      allowPermanentDelete: false
      enabled: true
      days: 7
    }
  }
}

resource Microsoft_Storage_storageAccounts_fileServices_storageAccounts_genaisadevcc01_name_default 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: storageAccounts_genaisadevcc01_name_resource
  name: 'default'
  sku: {
    name: 'Standard_LRS'
    tier: 'Standard'
  }
  properties: {
    protocolSettings: {
      smb: {}
    }
    cors: {
      corsRules: []
    }
    shareDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource storageAccounts_genaisadevcc01_name_storageAccounts_genaisadevcc01_name_a88842c0_b287_47a2_a2a3_3f12a59bf61f 'Microsoft.Storage/storageAccounts/privateEndpointConnections@2023-05-01' = {
  parent: storageAccounts_genaisadevcc01_name_resource
  name: '${storageAccounts_genaisadevcc01_name}.a88842c0-b287-47a2-a2a3-3f12a59bf61f'
  properties: {
    privateEndpoint: {}
    privateLinkServiceConnectionState: {
      status: 'Approved'
      description: 'Auto-Approved'
      actionRequired: 'None'
    }
  }
}

resource Microsoft_Storage_storageAccounts_queueServices_storageAccounts_genaisadevcc01_name_default 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storageAccounts_genaisadevcc01_name_resource
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
  }
}

resource Microsoft_Storage_storageAccounts_tableServices_storageAccounts_genaisadevcc01_name_default 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storageAccounts_genaisadevcc01_name_resource
  name: 'default'
  properties: {
    cors: {
      corsRules: []
    }
  }
}

resource prometheusRuleGroups_KubernetesRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name_resource 'Microsoft.AlertsManagement/prometheusRuleGroups@2023-03-01' = {
  name: prometheusRuleGroups_KubernetesRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    enabled: true
    description: 'Kubernetes Recording Rules RuleGroup'
    clusterName: 'genai-cluster-dev-cc-01'
    scopes: [
      accounts_defaultazuremonitorworkspace_cca_name_resource.id
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    rules: [
      {
        record: 'node_namespace_pod_container:container_cpu_usage_seconds_total:sum_irate'
        expression: 'sum by (cluster, namespace, pod, container) (  irate(container_cpu_usage_seconds_total{job="cadvisor", image!=""}[5m])) * on (cluster, namespace, pod) group_left(node) topk by (cluster, namespace, pod) (  1, max by(cluster, namespace, pod, node) (kube_pod_info{node!=""}))'
      }
      {
        record: 'node_namespace_pod_container:container_memory_working_set_bytes'
        expression: 'container_memory_working_set_bytes{job="cadvisor", image!=""}* on (namespace, pod) group_left(node) topk by(namespace, pod) (1,  max by(namespace, pod, node) (kube_pod_info{node!=""}))'
      }
      {
        record: 'node_namespace_pod_container:container_memory_rss'
        expression: 'container_memory_rss{job="cadvisor", image!=""}* on (namespace, pod) group_left(node) topk by(namespace, pod) (1,  max by(namespace, pod, node) (kube_pod_info{node!=""}))'
      }
      {
        record: 'node_namespace_pod_container:container_memory_cache'
        expression: 'container_memory_cache{job="cadvisor", image!=""}* on (namespace, pod) group_left(node) topk by(namespace, pod) (1,  max by(namespace, pod, node) (kube_pod_info{node!=""}))'
      }
      {
        record: 'node_namespace_pod_container:container_memory_swap'
        expression: 'container_memory_swap{job="cadvisor", image!=""}* on (namespace, pod) group_left(node) topk by(namespace, pod) (1,  max by(namespace, pod, node) (kube_pod_info{node!=""}))'
      }
      {
        record: 'cluster:namespace:pod_memory:active:kube_pod_container_resource_requests'
        expression: 'kube_pod_container_resource_requests{resource="memory",job="kube-state-metrics"}  * on (namespace, pod, cluster)group_left() max by (namespace, pod, cluster) (  (kube_pod_status_phase{phase=~"Pending|Running"} == 1))'
      }
      {
        record: 'namespace_memory:kube_pod_container_resource_requests:sum'
        expression: 'sum by (namespace, cluster) (    sum by (namespace, pod, cluster) (        max by (namespace, pod, container, cluster) (          kube_pod_container_resource_requests{resource="memory",job="kube-state-metrics"}        ) * on(namespace, pod, cluster) group_left() max by (namespace, pod, cluster) (          kube_pod_status_phase{phase=~"Pending|Running"} == 1        )    ))'
      }
      {
        record: 'cluster:namespace:pod_cpu:active:kube_pod_container_resource_requests'
        expression: 'kube_pod_container_resource_requests{resource="cpu",job="kube-state-metrics"}  * on (namespace, pod, cluster)group_left() max by (namespace, pod, cluster) (  (kube_pod_status_phase{phase=~"Pending|Running"} == 1))'
      }
      {
        record: 'namespace_cpu:kube_pod_container_resource_requests:sum'
        expression: 'sum by (namespace, cluster) (    sum by (namespace, pod, cluster) (        max by (namespace, pod, container, cluster) (          kube_pod_container_resource_requests{resource="cpu",job="kube-state-metrics"}        ) * on(namespace, pod, cluster) group_left() max by (namespace, pod, cluster) (          kube_pod_status_phase{phase=~"Pending|Running"} == 1        )    ))'
      }
      {
        record: 'cluster:namespace:pod_memory:active:kube_pod_container_resource_limits'
        expression: 'kube_pod_container_resource_limits{resource="memory",job="kube-state-metrics"}  * on (namespace, pod, cluster)group_left() max by (namespace, pod, cluster) (  (kube_pod_status_phase{phase=~"Pending|Running"} == 1))'
      }
      {
        record: 'namespace_memory:kube_pod_container_resource_limits:sum'
        expression: 'sum by (namespace, cluster) (    sum by (namespace, pod, cluster) (        max by (namespace, pod, container, cluster) (          kube_pod_container_resource_limits{resource="memory",job="kube-state-metrics"}        ) * on(namespace, pod, cluster) group_left() max by (namespace, pod, cluster) (          kube_pod_status_phase{phase=~"Pending|Running"} == 1        )    ))'
      }
      {
        record: 'cluster:namespace:pod_cpu:active:kube_pod_container_resource_limits'
        expression: 'kube_pod_container_resource_limits{resource="cpu",job="kube-state-metrics"}  * on (namespace, pod, cluster)group_left() max by (namespace, pod, cluster) ( (kube_pod_status_phase{phase=~"Pending|Running"} == 1) )'
      }
      {
        record: 'namespace_cpu:kube_pod_container_resource_limits:sum'
        expression: 'sum by (namespace, cluster) (    sum by (namespace, pod, cluster) (        max by (namespace, pod, container, cluster) (          kube_pod_container_resource_limits{resource="cpu",job="kube-state-metrics"}        ) * on(namespace, pod, cluster) group_left() max by (namespace, pod, cluster) (          kube_pod_status_phase{phase=~"Pending|Running"} == 1        )    ))'
      }
      {
        record: 'namespace_workload_pod:kube_pod_owner:relabel'
        expression: 'max by (cluster, namespace, workload, pod) (  label_replace(    label_replace(      kube_pod_owner{job="kube-state-metrics", owner_kind="ReplicaSet"},      "replicaset", "$1", "owner_name", "(.*)"    ) * on(replicaset, namespace) group_left(owner_name) topk by(replicaset, namespace) (      1, max by (replicaset, namespace, owner_name) (        kube_replicaset_owner{job="kube-state-metrics"}      )    ),    "workload", "$1", "owner_name", "(.*)"  ))'
        labels: {
          workload_type: 'deployment'
        }
      }
      {
        record: 'namespace_workload_pod:kube_pod_owner:relabel'
        expression: 'max by (cluster, namespace, workload, pod) (  label_replace(    kube_pod_owner{job="kube-state-metrics", owner_kind="DaemonSet"},    "workload", "$1", "owner_name", "(.*)"  ))'
        labels: {
          workload_type: 'daemonset'
        }
      }
      {
        record: 'namespace_workload_pod:kube_pod_owner:relabel'
        expression: 'max by (cluster, namespace, workload, pod) (  label_replace(    kube_pod_owner{job="kube-state-metrics", owner_kind="StatefulSet"},    "workload", "$1", "owner_name", "(.*)"  ))'
        labels: {
          workload_type: 'statefulset'
        }
      }
      {
        record: 'namespace_workload_pod:kube_pod_owner:relabel'
        expression: 'max by (cluster, namespace, workload, pod) (  label_replace(    kube_pod_owner{job="kube-state-metrics", owner_kind="Job"},    "workload", "$1", "owner_name", "(.*)"  ))'
        labels: {
          workload_type: 'job'
        }
      }
      {
        record: ':node_memory_MemAvailable_bytes:sum'
        expression: 'sum(  node_memory_MemAvailable_bytes{job="node"} or  (    node_memory_Buffers_bytes{job="node"} +    node_memory_Cached_bytes{job="node"} +    node_memory_MemFree_bytes{job="node"} +    node_memory_Slab_bytes{job="node"}  )) by (cluster)'
      }
      {
        record: 'cluster:node_cpu:ratio_rate5m'
        expression: 'sum(rate(node_cpu_seconds_total{job="node",mode!="idle",mode!="iowait",mode!="steal"}[5m])) by (cluster) /count(sum(node_cpu_seconds_total{job="node"}) by (cluster, instance, cpu)) by (cluster)'
      }
    ]
    interval: 'PT1M'
  }
}

resource prometheusRuleGroups_NodeAndKubernetesRecordingRulesRuleGroup_Win_genai_cluster_dev_c_name_resource 'Microsoft.AlertsManagement/prometheusRuleGroups@2023-03-01' = {
  name: prometheusRuleGroups_NodeAndKubernetesRecordingRulesRuleGroup_Win_genai_cluster_dev_c_name
  location: 'canadacentral'
  properties: {
    enabled: false
    description: 'Node and Kubernetes Recording Rules RuleGroup for Windows'
    clusterName: 'genai-cluster-dev-cc-01'
    scopes: [
      accounts_defaultazuremonitorworkspace_cca_name_resource.id
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    rules: [
      {
        record: 'node:windows_node_filesystem_usage:'
        expression: 'max by (instance,volume)((windows_logical_disk_size_bytes{job="windows-exporter"} - windows_logical_disk_free_bytes{job="windows-exporter"}) / windows_logical_disk_size_bytes{job="windows-exporter"})'
      }
      {
        record: 'node:windows_node_filesystem_avail:'
        expression: 'max by (instance, volume) (windows_logical_disk_free_bytes{job="windows-exporter"} / windows_logical_disk_size_bytes{job="windows-exporter"})'
      }
      {
        record: ':windows_node_net_utilisation:sum_irate'
        expression: 'sum(irate(windows_net_bytes_total{job="windows-exporter"}[5m]))'
      }
      {
        record: 'node:windows_node_net_utilisation:sum_irate'
        expression: 'sum by (instance) ((irate(windows_net_bytes_total{job="windows-exporter"}[5m])))'
      }
      {
        record: ':windows_node_net_saturation:sum_irate'
        expression: 'sum(irate(windows_net_packets_received_discarded_total{job="windows-exporter"}[5m])) + sum(irate(windows_net_packets_outbound_discarded_total{job="windows-exporter"}[5m]))'
      }
      {
        record: 'node:windows_node_net_saturation:sum_irate'
        expression: 'sum by (instance) ((irate(windows_net_packets_received_discarded_total{job="windows-exporter"}[5m]) + irate(windows_net_packets_outbound_discarded_total{job="windows-exporter"}[5m])))'
      }
      {
        record: 'windows_pod_container_available'
        expression: 'windows_container_available{job="windows-exporter", container_id != ""} * on(container_id) group_left(container, pod, namespace) max(kube_pod_container_info{job="kube-state-metrics", container_id != ""}) by(container, container_id, pod, namespace)'
      }
      {
        record: 'windows_container_total_runtime'
        expression: 'windows_container_cpu_usage_seconds_total{job="windows-exporter", container_id != ""} * on(container_id) group_left(container, pod, namespace) max(kube_pod_container_info{job="kube-state-metrics", container_id != ""}) by(container, container_id, pod, namespace)'
      }
      {
        record: 'windows_container_memory_usage'
        expression: 'windows_container_memory_usage_commit_bytes{job="windows-exporter", container_id != ""} * on(container_id) group_left(container, pod, namespace) max(kube_pod_container_info{job="kube-state-metrics", container_id != ""}) by(container, container_id, pod, namespace)'
      }
      {
        record: 'windows_container_private_working_set_usage'
        expression: 'windows_container_memory_usage_private_working_set_bytes{job="windows-exporter", container_id != ""} * on(container_id) group_left(container, pod, namespace) max(kube_pod_container_info{job="kube-state-metrics", container_id != ""}) by(container, container_id, pod, namespace)'
      }
      {
        record: 'windows_container_network_received_bytes_total'
        expression: 'windows_container_network_receive_bytes_total{job="windows-exporter", container_id != ""} * on(container_id) group_left(container, pod, namespace) max(kube_pod_container_info{job="kube-state-metrics", container_id != ""}) by(container, container_id, pod, namespace)'
      }
      {
        record: 'windows_container_network_transmitted_bytes_total'
        expression: 'windows_container_network_transmit_bytes_total{job="windows-exporter", container_id != ""} * on(container_id) group_left(container, pod, namespace) max(kube_pod_container_info{job="kube-state-metrics", container_id != ""}) by(container, container_id, pod, namespace)'
      }
      {
        record: 'kube_pod_windows_container_resource_memory_request'
        expression: 'max by (namespace, pod, container) (kube_pod_container_resource_requests{resource="memory",job="kube-state-metrics"}) * on(container,pod,namespace) (windows_pod_container_available)'
      }
      {
        record: 'kube_pod_windows_container_resource_memory_limit'
        expression: 'kube_pod_container_resource_limits{resource="memory",job="kube-state-metrics"} * on(container,pod,namespace) (windows_pod_container_available)'
      }
      {
        record: 'kube_pod_windows_container_resource_cpu_cores_request'
        expression: 'max by (namespace, pod, container) ( kube_pod_container_resource_requests{resource="cpu",job="kube-state-metrics"}) * on(container,pod,namespace) (windows_pod_container_available)'
      }
      {
        record: 'kube_pod_windows_container_resource_cpu_cores_limit'
        expression: 'kube_pod_container_resource_limits{resource="cpu",job="kube-state-metrics"} * on(container,pod,namespace) (windows_pod_container_available)'
      }
      {
        record: 'namespace_pod_container:windows_container_cpu_usage_seconds_total:sum_rate'
        expression: 'sum by (namespace, pod, container) (rate(windows_container_total_runtime{}[5m]))'
      }
    ]
    interval: 'PT1M'
  }
}

resource prometheusRuleGroups_NodeRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name_resource 'Microsoft.AlertsManagement/prometheusRuleGroups@2023-03-01' = {
  name: prometheusRuleGroups_NodeRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    enabled: true
    description: 'Node Recording Rules RuleGroup'
    clusterName: 'genai-cluster-dev-cc-01'
    scopes: [
      accounts_defaultazuremonitorworkspace_cca_name_resource.id
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    rules: [
      {
        record: 'instance:node_num_cpu:sum'
        expression: 'count without (cpu, mode) (  node_cpu_seconds_total{job="node",mode="idle"})'
      }
      {
        record: 'instance:node_cpu_utilisation:rate5m'
        expression: '1 - avg without (cpu) (  sum without (mode) (rate(node_cpu_seconds_total{job="node", mode=~"idle|iowait|steal"}[5m])))'
      }
      {
        record: 'instance:node_load1_per_cpu:ratio'
        expression: '(  node_load1{job="node"}/  instance:node_num_cpu:sum{job="node"})'
      }
      {
        record: 'instance:node_memory_utilisation:ratio'
        expression: '1 - (  (    node_memory_MemAvailable_bytes{job="node"}    or    (      node_memory_Buffers_bytes{job="node"}      +      node_memory_Cached_bytes{job="node"}      +      node_memory_MemFree_bytes{job="node"}      +      node_memory_Slab_bytes{job="node"}    )  )/  node_memory_MemTotal_bytes{job="node"})'
      }
      {
        record: 'instance:node_vmstat_pgmajfault:rate5m'
        expression: 'rate(node_vmstat_pgmajfault{job="node"}[5m])'
      }
      {
        record: 'instance_device:node_disk_io_time_seconds:rate5m'
        expression: 'rate(node_disk_io_time_seconds_total{job="node", device!=""}[5m])'
      }
      {
        record: 'instance_device:node_disk_io_time_weighted_seconds:rate5m'
        expression: 'rate(node_disk_io_time_weighted_seconds_total{job="node", device!=""}[5m])'
      }
      {
        record: 'instance:node_network_receive_bytes_excluding_lo:rate5m'
        expression: 'sum without (device) (  rate(node_network_receive_bytes_total{job="node", device!="lo"}[5m]))'
      }
      {
        record: 'instance:node_network_transmit_bytes_excluding_lo:rate5m'
        expression: 'sum without (device) (  rate(node_network_transmit_bytes_total{job="node", device!="lo"}[5m]))'
      }
      {
        record: 'instance:node_network_receive_drop_excluding_lo:rate5m'
        expression: 'sum without (device) (  rate(node_network_receive_drop_total{job="node", device!="lo"}[5m]))'
      }
      {
        record: 'instance:node_network_transmit_drop_excluding_lo:rate5m'
        expression: 'sum without (device) (  rate(node_network_transmit_drop_total{job="node", device!="lo"}[5m]))'
      }
    ]
    interval: 'PT1M'
  }
}

resource prometheusRuleGroups_NodeRecordingRulesRuleGroup_Win_genai_cluster_dev_cc_01_name_resource 'Microsoft.AlertsManagement/prometheusRuleGroups@2023-03-01' = {
  name: prometheusRuleGroups_NodeRecordingRulesRuleGroup_Win_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    enabled: false
    description: 'Node Recording Rules RuleGroup for Windows'
    clusterName: 'genai-cluster-dev-cc-01'
    scopes: [
      accounts_defaultazuremonitorworkspace_cca_name_resource.id
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    rules: [
      {
        record: 'node:windows_node:sum'
        expression: 'count (windows_system_system_up_time{job="windows-exporter"})'
      }
      {
        record: 'node:windows_node_num_cpu:sum'
        expression: 'count by (instance) (sum by (instance, core) (windows_cpu_time_total{job="windows-exporter"}))'
      }
      {
        record: ':windows_node_cpu_utilisation:avg5m'
        expression: '1 - avg(rate(windows_cpu_time_total{job="windows-exporter",mode="idle"}[5m]))'
      }
      {
        record: 'node:windows_node_cpu_utilisation:avg5m'
        expression: '1 - avg by (instance) (rate(windows_cpu_time_total{job="windows-exporter",mode="idle"}[5m]))'
      }
      {
        record: ':windows_node_memory_utilisation:'
        expression: '1 -sum(windows_memory_available_bytes{job="windows-exporter"})/sum(windows_os_visible_memory_bytes{job="windows-exporter"})'
      }
      {
        record: ':windows_node_memory_MemFreeCached_bytes:sum'
        expression: 'sum(windows_memory_available_bytes{job="windows-exporter"} + windows_memory_cache_bytes{job="windows-exporter"})'
      }
      {
        record: 'node:windows_node_memory_totalCached_bytes:sum'
        expression: '(windows_memory_cache_bytes{job="windows-exporter"} + windows_memory_modified_page_list_bytes{job="windows-exporter"} + windows_memory_standby_cache_core_bytes{job="windows-exporter"} + windows_memory_standby_cache_normal_priority_bytes{job="windows-exporter"} + windows_memory_standby_cache_reserve_bytes{job="windows-exporter"})'
      }
      {
        record: ':windows_node_memory_MemTotal_bytes:sum'
        expression: 'sum(windows_os_visible_memory_bytes{job="windows-exporter"})'
      }
      {
        record: 'node:windows_node_memory_bytes_available:sum'
        expression: 'sum by (instance) ((windows_memory_available_bytes{job="windows-exporter"}))'
      }
      {
        record: 'node:windows_node_memory_bytes_total:sum'
        expression: 'sum by (instance) (windows_os_visible_memory_bytes{job="windows-exporter"})'
      }
      {
        record: 'node:windows_node_memory_utilisation:ratio'
        expression: '(node:windows_node_memory_bytes_total:sum - node:windows_node_memory_bytes_available:sum) / scalar(sum(node:windows_node_memory_bytes_total:sum))'
      }
      {
        record: 'node:windows_node_memory_utilisation:'
        expression: '1 - (node:windows_node_memory_bytes_available:sum / node:windows_node_memory_bytes_total:sum)'
      }
      {
        record: 'node:windows_node_memory_swap_io_pages:irate'
        expression: 'irate(windows_memory_swap_page_operations_total{job="windows-exporter"}[5m])'
      }
      {
        record: ':windows_node_disk_utilisation:avg_irate'
        expression: 'avg(irate(windows_logical_disk_read_seconds_total{job="windows-exporter"}[5m]) + irate(windows_logical_disk_write_seconds_total{job="windows-exporter"}[5m]))'
      }
      {
        record: 'node:windows_node_disk_utilisation:avg_irate'
        expression: 'avg by (instance) ((irate(windows_logical_disk_read_seconds_total{job="windows-exporter"}[5m]) + irate(windows_logical_disk_write_seconds_total{job="windows-exporter"}[5m])))'
      }
    ]
    interval: 'PT1M'
  }
}

resource prometheusRuleGroups_UXRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name_resource 'Microsoft.AlertsManagement/prometheusRuleGroups@2023-03-01' = {
  name: prometheusRuleGroups_UXRecordingRulesRuleGroup_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    enabled: true
    description: 'UX Recording Rules for Linux'
    clusterName: 'genai-cluster-dev-cc-01'
    scopes: [
      accounts_defaultazuremonitorworkspace_cca_name_resource.id
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    rules: [
      {
        record: 'ux:pod_cpu_usage:sum_irate'
        expression: '(sum by (namespace, pod, cluster, microsoft_resourceid) (\n\tirate(container_cpu_usage_seconds_total{container != "", pod != "", job = "cadvisor"}[5m])\n)) * on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n(max by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (kube_pod_info{pod != "", job = "kube-state-metrics"}))'
      }
      {
        record: 'ux:controller_cpu_usage:sum_irate'
        expression: 'sum by (namespace, node, cluster, created_by_name, created_by_kind, microsoft_resourceid) (\nux:pod_cpu_usage:sum_irate\n)\n'
      }
      {
        record: 'ux:pod_workingset_memory:sum'
        expression: '(\n\t    sum by (namespace, pod, cluster, microsoft_resourceid) (\n\t\tcontainer_memory_working_set_bytes{container != "", pod != "", job = "cadvisor"}\n\t    )\n\t) * on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n(max by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (kube_pod_info{pod != "", job = "kube-state-metrics"}))'
      }
      {
        record: 'ux:controller_workingset_memory:sum'
        expression: 'sum by (namespace, node, cluster, created_by_name, created_by_kind, microsoft_resourceid) (\nux:pod_workingset_memory:sum\n)'
      }
      {
        record: 'ux:pod_rss_memory:sum'
        expression: '(\n\t    sum by (namespace, pod, cluster, microsoft_resourceid) (\n\t\tcontainer_memory_rss{container != "", pod != "", job = "cadvisor"}\n\t    )\n\t) * on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n(max by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (kube_pod_info{pod != "", job = "kube-state-metrics"}))'
      }
      {
        record: 'ux:controller_rss_memory:sum'
        expression: 'sum by (namespace, node, cluster, created_by_name, created_by_kind, microsoft_resourceid) (\nux:pod_rss_memory:sum\n)'
      }
      {
        record: 'ux:pod_container_count:sum'
        expression: 'sum by (node, created_by_name, created_by_kind, namespace, cluster, pod, microsoft_resourceid) (\n(\n(\nsum by (container, pod, namespace, cluster, microsoft_resourceid) (kube_pod_container_info{container != "", pod != "", container_id != "", job = "kube-state-metrics"})\nor sum by (container, pod, namespace, cluster, microsoft_resourceid) (kube_pod_init_container_info{container != "", pod != "", container_id != "", job = "kube-state-metrics"})\n)\n* on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n(\nmax by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (\n\tkube_pod_info{pod != "", job = "kube-state-metrics"}\n)\n)\n)\n\n)'
      }
      {
        record: 'ux:controller_container_count:sum'
        expression: 'sum by (node, created_by_name, created_by_kind, namespace, cluster, microsoft_resourceid) (\nux:pod_container_count:sum\n)'
      }
      {
        record: 'ux:pod_container_restarts:max'
        expression: 'max by (node, created_by_name, created_by_kind, namespace, cluster, pod, microsoft_resourceid) (\n(\n(\nmax by (container, pod, namespace, cluster, microsoft_resourceid) (kube_pod_container_status_restarts_total{container != "", pod != "", job = "kube-state-metrics"})\nor sum by (container, pod, namespace, cluster, microsoft_resourceid) (kube_pod_init_status_restarts_total{container != "", pod != "", job = "kube-state-metrics"})\n)\n* on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n(\nmax by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (\n\tkube_pod_info{pod != "", job = "kube-state-metrics"}\n)\n)\n)\n\n)'
      }
      {
        record: 'ux:controller_container_restarts:max'
        expression: 'max by (node, created_by_name, created_by_kind, namespace, cluster, microsoft_resourceid) (\nux:pod_container_restarts:max\n)'
      }
      {
        record: 'ux:pod_resource_limit:sum'
        expression: '(sum by (cluster, pod, namespace, resource, microsoft_resourceid) (\n(\n\tmax by (cluster, microsoft_resourceid, pod, container, namespace, resource)\n\t (kube_pod_container_resource_limits{container != "", pod != "", job = "kube-state-metrics"})\n)\n)unless (count by (pod, namespace, cluster, resource, microsoft_resourceid)\n\t(kube_pod_container_resource_limits{container != "", pod != "", job = "kube-state-metrics"})\n!= on (pod, namespace, cluster, microsoft_resourceid) group_left()\n sum by (pod, namespace, cluster, microsoft_resourceid)\n (kube_pod_container_info{container != "", pod != "", job = "kube-state-metrics"}) \n)\n\n)* on (namespace, pod, cluster, microsoft_resourceid) group_left (node, created_by_kind, created_by_name)\n(\n\tkube_pod_info{pod != "", job = "kube-state-metrics"}\n)'
      }
      {
        record: 'ux:controller_resource_limit:sum'
        expression: 'sum by (cluster, namespace, created_by_name, created_by_kind, node, resource, microsoft_resourceid) (\nux:pod_resource_limit:sum\n)'
      }
      {
        record: 'ux:controller_pod_phase_count:sum'
        expression: 'sum by (cluster, phase, node, created_by_kind, created_by_name, namespace, microsoft_resourceid) ( (\n(kube_pod_status_phase{job="kube-state-metrics",pod!=""})\n or (label_replace((count(kube_pod_deletion_timestamp{job="kube-state-metrics",pod!=""}) by (namespace, pod, cluster, microsoft_resourceid) * count(kube_pod_status_reason{reason="NodeLost", job="kube-state-metrics"} == 0) by (namespace, pod, cluster, microsoft_resourceid)), "phase", "terminating", "", ""))) * on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n(\nmax by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (\nkube_pod_info{job="kube-state-metrics",pod!=""}\n)\n)\n)'
      }
      {
        record: 'ux:cluster_pod_phase_count:sum'
        expression: 'sum by (cluster, phase, node, namespace, microsoft_resourceid) (\nux:controller_pod_phase_count:sum\n)'
      }
      {
        record: 'ux:node_cpu_usage:sum_irate'
        expression: 'sum by (instance, cluster, microsoft_resourceid) (\n(1 - irate(node_cpu_seconds_total{job="node", mode="idle"}[5m]))\n)'
      }
      {
        record: 'ux:node_memory_usage:sum'
        expression: 'sum by (instance, cluster, microsoft_resourceid) ((\nnode_memory_MemTotal_bytes{job = "node"}\n- node_memory_MemFree_bytes{job = "node"} \n- node_memory_cached_bytes{job = "node"}\n- node_memory_buffers_bytes{job = "node"}\n))'
      }
      {
        record: 'ux:node_network_receive_drop_total:sum_irate'
        expression: 'sum by (instance, cluster, microsoft_resourceid) (irate(node_network_receive_drop_total{job="node", device!="lo"}[5m]))'
      }
      {
        record: 'ux:node_network_transmit_drop_total:sum_irate'
        expression: 'sum by (instance, cluster, microsoft_resourceid) (irate(node_network_transmit_drop_total{job="node", device!="lo"}[5m]))'
      }
    ]
    interval: 'PT1M'
  }
}

resource prometheusRuleGroups_UXRecordingRulesRuleGroup_Win_genai_cluster_dev_cc_01_name_resource 'Microsoft.AlertsManagement/prometheusRuleGroups@2023-03-01' = {
  name: prometheusRuleGroups_UXRecordingRulesRuleGroup_Win_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    enabled: false
    description: 'UX Recording Rules for Windows'
    clusterName: 'genai-cluster-dev-cc-01'
    scopes: [
      accounts_defaultazuremonitorworkspace_cca_name_resource.id
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    rules: [
      {
        record: 'ux:pod_cpu_usage_windows:sum_irate'
        expression: 'sum by (cluster, pod, namespace, node, created_by_kind, created_by_name, microsoft_resourceid) (\n\t(\n\t\tmax by (instance, container_id, cluster, microsoft_resourceid) (\n\t\t\tirate(windows_container_cpu_usage_seconds_total{ container_id != "", job = "windows-exporter"}[5m])\n\t\t) * on (container_id, cluster, microsoft_resourceid) group_left (container, pod, namespace) (\n\t\t\tmax by (container, container_id, pod, namespace, cluster, microsoft_resourceid) (\n\t\t\t\tkube_pod_container_info{container != "", pod != "", container_id != "", job = "kube-state-metrics"}\n\t\t\t)\n\t\t)\n\t) * on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n\t(\n\t\tmax by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (\n\t\t  kube_pod_info{ pod != "", job = "kube-state-metrics"}\n\t\t)\n\t)\n)'
      }
      {
        record: 'ux:controller_cpu_usage_windows:sum_irate'
        expression: 'sum by (namespace, node, cluster, created_by_name, created_by_kind, microsoft_resourceid) (\nux:pod_cpu_usage_windows:sum_irate\n)\n'
      }
      {
        record: 'ux:pod_workingset_memory_windows:sum'
        expression: 'sum by (cluster, pod, namespace, node, created_by_kind, created_by_name, microsoft_resourceid) (\n\t(\n\t\tmax by (instance, container_id, cluster, microsoft_resourceid) (\n\t\t\twindows_container_memory_usage_private_working_set_bytes{ container_id != "", job = "windows-exporter"}\n\t\t) * on (container_id, cluster, microsoft_resourceid) group_left (container, pod, namespace) (\n\t\t\tmax by (container, container_id, pod, namespace, cluster, microsoft_resourceid) (\n\t\t\t\tkube_pod_container_info{container != "", pod != "", container_id != "", job = "kube-state-metrics"}\n\t\t\t)\n\t\t)\n\t) * on (pod, namespace, cluster, microsoft_resourceid) group_left (node, created_by_name, created_by_kind)\n\t(\n\t\tmax by (node, created_by_name, created_by_kind, pod, namespace, cluster, microsoft_resourceid) (\n\t\t  kube_pod_info{ pod != "", job = "kube-state-metrics"}\n\t\t)\n\t)\n)'
      }
      {
        record: 'ux:controller_workingset_memory_windows:sum'
        expression: 'sum by (namespace, node, cluster, created_by_name, created_by_kind, microsoft_resourceid) (\nux:pod_workingset_memory_windows:sum\n)'
      }
      {
        record: 'ux:node_cpu_usage_windows:sum_irate'
        expression: 'sum by (instance, cluster, microsoft_resourceid) (\n(1 - irate(windows_cpu_time_total{job="windows-exporter", mode="idle"}[5m]))\n)'
      }
      {
        record: 'ux:node_memory_usage_windows:sum'
        expression: 'sum by (instance, cluster, microsoft_resourceid) ((\nwindows_os_visible_memory_bytes{job = "windows-exporter"}\n- windows_memory_available_bytes{job = "windows-exporter"}\n))'
      }
      {
        record: 'ux:node_network_packets_received_drop_total_windows:sum_irate'
        expression: 'sum by (instance, cluster, microsoft_resourceid) (irate(windows_net_packets_received_discarded_total{job="windows-exporter", device!="lo"}[5m]))'
      }
      {
        record: 'ux:node_network_packets_outbound_drop_total_windows:sum_irate'
        expression: 'sum by (instance, cluster, microsoft_resourceid) (irate(windows_net_packets_outbound_discarded_total{job="windows-exporter", device!="lo"}[5m]))'
      }
    ]
    interval: 'PT1M'
  }
}

resource smartdetectoralertrules_failure_anomalies_genai_insights_dev_cc_01_name_resource 'microsoft.alertsmanagement/smartdetectoralertrules@2021-04-01' = {
  name: smartdetectoralertrules_failure_anomalies_genai_insights_dev_cc_01_name
  location: 'global'
  properties: {
    description: 'Failure Anomalies notifies you of an unusual rise in the rate of failed HTTP requests or dependency calls.'
    state: 'Enabled'
    severity: 'Sev3'
    frequency: 'PT1M'
    detector: {
      id: 'FailureAnomaliesDetector'
    }
    scope: [
      components_genai_insights_dev_cc_01_name_resource.id
    ]
    actionGroups: {
      groupIds: [
        actionGroups_Application_Insights_Smart_Detection_name_resource.id
      ]
    }
  }
}

resource managedClusters_genai_cluster_dev_cc_01_name_agentpool 'Microsoft.ContainerService/managedClusters/agentPools@2024-08-01' = {
  parent: managedClusters_genai_cluster_dev_cc_01_name_resource
  name: 'agentpool'
  properties: {
    count: 2
    vmSize: 'Standard_D4ds_v5'
    osDiskSizeGB: 128
    osDiskType: 'Ephemeral'
    kubeletDiskType: 'OS'
    vnetSubnetID: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet.id
    maxPods: 110
    type: 'VirtualMachineScaleSets'
    maxCount: 5
    minCount: 2
    enableAutoScaling: true
    powerState: {
      code: 'Running'
    }
    orchestratorVersion: '1.31.3'
    enableNodePublicIP: false
    mode: 'System'
    osType: 'Linux'
    osSKU: 'Ubuntu'
    upgradeSettings: {
      maxSurge: '10%'
    }
    enableFIPS: false
    securityProfile: {
      enableVTPM: false
      enableSecureBoot: false
    }
  }
}

resource dataCollectionRules_MSProm_canadacentral_genai_cluster_dev_cc_01_name_resource 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dataCollectionRules_MSProm_canadacentral_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  kind: 'Linux'
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoints_MSProm_canadacentral_genai_cluster_dev_cc_01_name_resource.id
    dataSources: {
      prometheusForwarder: [
        {
          streams: [
            'Microsoft-PrometheusMetrics'
          ]
          labelIncludeFilter: {}
          name: 'PrometheusDataSource'
        }
      ]
    }
    destinations: {
      monitoringAccounts: [
        {
          accountResourceId: accounts_defaultazuremonitorworkspace_cca_name_resource.id
          name: 'MonitoringAccount1'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-PrometheusMetrics'
        ]
        destinations: [
          'MonitoringAccount1'
        ]
      }
    ]
  }
}

resource metricAlerts_CPU_Usage_Percentage_genai_cluster_dev_cc_01_name_resource 'microsoft.insights/metricAlerts@2018-03-01' = {
  name: metricAlerts_CPU_Usage_Percentage_genai_cluster_dev_cc_01_name
  location: 'Global'
  properties: {
    severity: 3
    enabled: true
    scopes: [
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      allOf: [
        {
          threshold: 95
          name: 'Metric1'
          metricNamespace: 'Microsoft.ContainerService/managedClusters'
          metricName: 'node_cpu_usage_percentage'
          operator: 'GreaterThan'
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria'
    }
    targetResourceType: 'Microsoft.ContainerService/managedClusters'
    actions: [
      {
        actionGroupId: actionGroups_RecommendedAlertRules_AG_1_name_resource.id
        webHookProperties: {}
      }
    ]
  }
}

resource metricAlerts_Memory_Working_Set_Percentage_genai_cluster_dev_cc_01_name_resource 'microsoft.insights/metricAlerts@2018-03-01' = {
  name: metricAlerts_Memory_Working_Set_Percentage_genai_cluster_dev_cc_01_name
  location: 'Global'
  properties: {
    severity: 3
    enabled: true
    scopes: [
      managedClusters_genai_cluster_dev_cc_01_name_resource.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      allOf: [
        {
          threshold: 100
          name: 'Metric1'
          metricNamespace: 'Microsoft.ContainerService/managedClusters'
          metricName: 'node_memory_working_set_percentage'
          operator: 'GreaterThan'
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
      'odata.type': 'Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria'
    }
    targetResourceType: 'Microsoft.ContainerService/managedClusters'
    actions: [
      {
        actionGroupId: actionGroups_RecommendedAlertRules_AG_1_name_resource.id
        webHookProperties: {}
      }
    ]
  }
}

resource bastionHosts_genai_accelerator_vnet_dev_cc_01_Bastion_name_resource 'Microsoft.Network/bastionHosts@2024-03-01' = {
  name: bastionHosts_genai_accelerator_vnet_dev_cc_01_Bastion_name
  location: 'canadacentral'
  sku: {
    name: 'Basic'
  }
  properties: {
    dnsName: 'bst-3163aafa-f535-4f36-9252-60ca3a58d4c0.bastion.azure.com'
    scaleUnits: 2
    ipConfigurations: [
      {
        name: 'IpConf'
        id: '${bastionHosts_genai_accelerator_vnet_dev_cc_01_Bastion_name_resource.id}/bastionHostIpConfigurations/IpConf'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIPAddresses_genai_accelerator_vnet_dev_cc_01_bastion_name_resource.id
          }
          subnet: {
            id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_AzureBastionSubnet.id
          }
        }
      }
    ]
  }
}

resource networkInterfaces_genai_jumpbox_vm_0185_z1_name_resource 'Microsoft.Network/networkInterfaces@2024-03-01' = {
  name: networkInterfaces_genai_jumpbox_vm_0185_z1_name
  location: 'canadacentral'
  kind: 'Regular'
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        id: '${networkInterfaces_genai_jumpbox_vm_0185_z1_name_resource.id}/ipConfigurations/ipconfig1'
        type: 'Microsoft.Network/networkInterfaces/ipConfigurations'
        properties: {
          privateIPAddress: '10.0.0.9'
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIPAddresses_genai_jumpbox_vm_01_ip_name_resource.id
            properties: {
              deleteOption: 'Delete'
            }
          }
          subnet: {
            id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet.id
          }
          primary: true
          privateIPAddressVersion: 'IPv4'
        }
      }
    ]
    dnsSettings: {
      dnsServers: []
    }
    enableAcceleratedNetworking: false
    enableIPForwarding: false
    disableTcpStateTracking: false
    nicType: 'Standard'
    auxiliaryMode: 'None'
    auxiliarySku: 'None'
  }
}

resource privateDnsZones_private_contoso_com_name_private_dns_link 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: privateDnsZones_private_contoso_com_name_resource
  name: 'private-dns-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource.id
    }
  }
}

resource privateDnsZones_privatelink_blob_core_windows_net_name_yfa2gnxr5ihue 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: privateDnsZones_privatelink_blob_core_windows_net_name_resource
  name: 'yfa2gnxr5ihue'
  location: 'global'
  properties: {
    registrationEnabled: false
    resolutionPolicy: 'Default'
    virtualNetwork: {
      id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource.id
    }
  }
}

resource privateDnsZones_privatelink_search_windows_net_name_yfa2gnxr5ihue 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: privateDnsZones_privatelink_search_windows_net_name_resource
  name: 'yfa2gnxr5ihue'
  location: 'global'
  properties: {
    registrationEnabled: false
    resolutionPolicy: 'Default'
    virtualNetwork: {
      id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource.id
    }
  }
}

resource privateEndpoints_genai_pe_dev_cc_01_name_resource 'Microsoft.Network/privateEndpoints@2024-03-01' = {
  name: privateEndpoints_genai_pe_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    privateLinkServiceConnections: [
      {
        name: '${privateEndpoints_genai_pe_dev_cc_01_name}_355d5df0-7f72-4ea3-b16a-7b704a60301b'
        id: '${privateEndpoints_genai_pe_dev_cc_01_name_resource.id}/privateLinkServiceConnections/${privateEndpoints_genai_pe_dev_cc_01_name}_355d5df0-7f72-4ea3-b16a-7b704a60301b'
        properties: {
          privateLinkServiceId: searchServices_genai_search_dev_cc_01_name_resource.id
          groupIds: [
            'searchService'
          ]
          privateLinkServiceConnectionState: {
            status: 'Approved'
            description: 'Auto-approved'
            actionsRequired: 'None'
          }
        }
      }
    ]
    manualPrivateLinkServiceConnections: []
    subnet: {
      id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet.id
    }
    ipConfigurations: []
    customDnsConfigs: [
      {
        fqdn: 'genai-search-dev-cc-01.search.windows.net'
        ipAddresses: [
          '10.0.0.12'
        ]
      }
    ]
  }
}

resource privateEndpoints_genai_pe_sa_dev_cc_01_name_resource 'Microsoft.Network/privateEndpoints@2024-03-01' = {
  name: privateEndpoints_genai_pe_sa_dev_cc_01_name
  location: 'canadacentral'
  properties: {
    privateLinkServiceConnections: [
      {
        name: '${privateEndpoints_genai_pe_sa_dev_cc_01_name}_65f452f3-2b4b-467a-b414-b956eaad801b'
        id: '${privateEndpoints_genai_pe_sa_dev_cc_01_name_resource.id}/privateLinkServiceConnections/${privateEndpoints_genai_pe_sa_dev_cc_01_name}_65f452f3-2b4b-467a-b414-b956eaad801b'
        properties: {
          privateLinkServiceId: storageAccounts_genaisadevcc01_name_resource.id
          groupIds: [
            'blob'
          ]
          privateLinkServiceConnectionState: {
            status: 'Approved'
            description: 'Auto-Approved'
            actionsRequired: 'None'
          }
        }
      }
    ]
    manualPrivateLinkServiceConnections: []
    subnet: {
      id: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet.id
    }
    ipConfigurations: []
    customDnsConfigs: [
      {
        fqdn: 'genaisadevcc01.blob.core.windows.net'
        ipAddresses: [
          '10.0.0.11'
        ]
      }
    ]
  }
}

resource virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet 'Microsoft.Network/virtualNetworks/subnets@2024-03-01' = {
  name: '${virtualNetworks_genai_accelerator_vnet_dev_cc_01_name}/app-subnet'
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
  dependsOn: [
    virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_resource
  ]
}

resource searchServices_genai_search_dev_cc_01_name_genai_pe_dev_cc_01_51cbb441_cb10_448b_ab52_04af66c84a44 'Microsoft.Search/searchServices/privateEndpointConnections@2024-06-01-preview' = {
  parent: searchServices_genai_search_dev_cc_01_name_resource
  name: 'genai-pe-dev-cc-01.51cbb441-cb10-448b-ab52-04af66c84a44'
  properties: {
    privateEndpoint: {
      id: privateEndpoints_genai_pe_dev_cc_01_name_resource.id
    }
    privateLinkServiceConnectionState: {
      status: 'Approved'
      description: 'Auto-approved'
      actionsRequired: 'None'
    }
    provisioningState: 'Succeeded'
    groupId: 'searchService'
  }
}

resource managedClusters_genai_cluster_dev_cc_01_name_resource 'Microsoft.ContainerService/managedClusters@2024-08-01' = {
  name: managedClusters_genai_cluster_dev_cc_01_name
  location: 'canadacentral'
  sku: {
    name: 'Base'
    tier: 'Free'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    kubernetesVersion: '1.31.3'
    dnsPrefix: '${managedClusters_genai_cluster_dev_cc_01_name}-dns'
    agentPoolProfiles: [
      {
        name: 'agentpool'
        count: 2
        vmSize: 'Standard_D4ds_v5'
        osDiskSizeGB: 128
        osDiskType: 'Ephemeral'
        kubeletDiskType: 'OS'
        vnetSubnetID: virtualNetworks_genai_accelerator_vnet_dev_cc_01_name_app_subnet.id
        maxPods: 110
        type: 'VirtualMachineScaleSets'
        maxCount: 5
        minCount: 2
        enableAutoScaling: true
        powerState: {
          code: 'Running'
        }
        orchestratorVersion: '1.31.3'
        enableNodePublicIP: false
        mode: 'System'
        osType: 'Linux'
        osSKU: 'Ubuntu'
        upgradeSettings: {
          maxSurge: '10%'
        }
        enableFIPS: false
        securityProfile: {
          enableVTPM: false
          enableSecureBoot: false
        }
      }
    ]
    windowsProfile: {
      adminUsername: 'azureuser'
      enableCSIProxy: true
    }
    servicePrincipalProfile: {
      clientId: 'msi'
    }
    addonProfiles: {
      azureKeyvaultSecretsProvider: {
        enabled: false
      }
      azurepolicy: {
        enabled: true
      }
      omsAgent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource.id
          useAADAuth: 'true'
        }
      }
    }
    nodeResourceGroup: 'MC_rg-genai-accelerator-dev-cc-01_${managedClusters_genai_cluster_dev_cc_01_name}_canadacentral'
    enableRBAC: true
    supportPlan: 'KubernetesOfficial'
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkPolicy: 'calico'
      networkDataplane: 'azure'
      loadBalancerSku: 'Standard'
      loadBalancerProfile: {
        managedOutboundIPs: {
          count: 1
        }
        effectiveOutboundIPs: [
          {
            id: publicIPAddresses_31bf409f_46ce_4f56_bba4_df1db3877f0c_externalid
          }
        ]
        backendPoolType: 'nodeIPConfiguration'
      }
      podCidr: '10.244.0.0/16'
      serviceCidr: '10.1.0.0/16'
      dnsServiceIP: '10.1.0.10'
      outboundType: 'loadBalancer'
      podCidrs: [
        '10.244.0.0/16'
      ]
      serviceCidrs: [
        '10.1.0.0/16'
      ]
      ipFamilies: [
        'IPv4'
      ]
    }
    identityProfile: {
      kubeletidentity: {
        resourceId: userAssignedIdentities_genai_cluster_dev_cc_01_agentpool_externalid
        clientId: '31d46f3a-dba3-405f-8b57-47fbf5683fb5'
        objectId: '4bad389a-2c07-4f89-94c0-fdf43245924d'
      }
    }
    autoScalerProfile: {
      'balance-similar-node-groups': 'false'
      'daemonset-eviction-for-empty-nodes': false
      'daemonset-eviction-for-occupied-nodes': true
      expander: 'random'
      'ignore-daemonsets-utilization': false
      'max-empty-bulk-delete': '10'
      'max-graceful-termination-sec': '600'
      'max-node-provision-time': '15m'
      'max-total-unready-percentage': '45'
      'new-pod-scale-up-delay': '0s'
      'ok-total-unready-count': '3'
      'scale-down-delay-after-add': '10m'
      'scale-down-delay-after-delete': '10s'
      'scale-down-delay-after-failure': '3m'
      'scale-down-unneeded-time': '10m'
      'scale-down-unready-time': '20m'
      'scale-down-utilization-threshold': '0.5'
      'scan-interval': '10s'
      'skip-nodes-with-local-storage': 'false'
      'skip-nodes-with-system-pods': 'true'
    }
    autoUpgradeProfile: {
      upgradeChannel: 'patch'
      nodeOSUpgradeChannel: 'NodeImage'
    }
    disableLocalAccounts: false
    securityProfile: {
      imageCleaner: {
        enabled: true
        intervalHours: 168
      }
      workloadIdentity: {
        enabled: true
      }
    }
    storageProfile: {
      diskCSIDriver: {
        enabled: true
      }
      fileCSIDriver: {
        enabled: true
      }
      snapshotController: {
        enabled: true
      }
    }
    oidcIssuerProfile: {
      enabled: true
    }
    ingressProfile: {
      webAppRouting: {
        enabled: true
        dnsZoneResourceIds: [
          privateDnsZones_private_contoso_com_name_resource.id
        ]
      }
    }
    workloadAutoScalerProfile: {}
    azureMonitorProfile: {
      metrics: {
        enabled: true
        kubeStateMetrics: {}
      }
    }
    serviceMeshProfile: {
      mode: 'Istio'
      istio: {
        components: {
          ingressGateways: [
            {
              mode: 'Internal'
              enabled: true
            }
            {
              mode: 'External'
              enabled: managedClusters_genai_cluster_dev_cc_01_enabled
            }
          ]
        }
        revisions: [
          'asm-1-23'
        ]
      }
    }
    metricsProfile: {
      costAnalysis: {
        enabled: false
      }
    }
  }
}
