module vnetModule 'vnet.bicep' = {
  name: 'vnetDeployment'
  params: {
    di_accelerator_vnet_dev_cc_01_name: 'di-accelerator-vnet-dev-cc-01'
    location: 'canadacentral'
  }
}

module aksModule 'aks.bicep' = {
  name: 'aksDeployment'
  params: {
    aksClusterName: 'di-aks-cluster-dev-cc-01'
    location: 'canadacentral'
    subnetId: vnetModule.outputs.appSubnetId
  }
}
