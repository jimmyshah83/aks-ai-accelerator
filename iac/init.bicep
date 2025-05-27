module vnetModule 'vnet.bicep' = {
  name: 'vnetDeployment'
  params: {
    di_accelerator_vnet_dev_cc_01_name: 'di-accelerator-vnet-dev-cc-01'
    location: 'canadacentral'
  }
}
