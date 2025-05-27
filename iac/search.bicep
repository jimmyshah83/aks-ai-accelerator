param searchServices_genai_search_dev_cc_01_name string = 'genai-search-dev-cc-01'

resource searchServices_genai_search_dev_cc_01_name_resource 'Microsoft.Search/searchServices@2025-02-01-preview' = {
  name: searchServices_genai_search_dev_cc_01_name
  location: 'Canada Central'
  sku: {
    name: 'basic'
  }
  properties: {
    replicaCount: 1
    partitionCount: 1
    endpoint: 'https://${searchServices_genai_search_dev_cc_01_name}.search.windows.net'
    hostingMode: 'Default'
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
