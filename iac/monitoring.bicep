// Monitoring resources module
// ...monitoring-related resources will be moved here from main.bicep...

param workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name string = 'workspaces-57123c17-af1a-4ec2-9494-a214fb148bf4-rg-genai-accelerator-ccan'
param accounts_defaultazuremonitorworkspace_cca_name string = 'accounts-defaultazuremonitorworkspace-cca'
param dataCollectionEndpoints_MSProm_canadacentral_genai_cluster_dev_cc_01_name string = 'dce-msprom-canadacentral-genai-cluster-dev-cc-01'
param actionGroups_Application_Insights_Smart_Detection_name string = 'actiongroups-application-insights-smart-detection'
param actionGroups_RecommendedAlertRules_AG_1_name string = 'actiongroups-recommendedalertrules-ag-1'

resource workspaces_57123c17_af1a_4ec2_9494_a214fb148bf4_rg_genai_accelerator_CCAN_name_resource 'Microsoft.OperationalInsights/workspaces@2025-02-01' = {
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
      dailyQuotaGb: json('-1')
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource accounts_defaultazuremonitorworkspace_cca_name_resource 'microsoft.monitor/accounts@2023-04-03' = {
  name: accounts_defaultazuremonitorworkspace_cca_name
  location: 'canadacentral'
  properties: {
    publicNetworkAccess: 'Enabled'
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

resource actionGroups_Application_Insights_Smart_Detection_name_resource 'microsoft.insights/actionGroups@2024-10-01-preview' = {
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

resource actionGroups_RecommendedAlertRules_AG_1_name_resource 'microsoft.insights/actionGroups@2024-10-01-preview' = {
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
