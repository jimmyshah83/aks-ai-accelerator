param aksClusterName string = 'di-aks-cluster-dev-cc-01'
param location string = 'canadacentral'
param subnetId string

resource aks 'Microsoft.ContainerService/managedClusters@2024-01-01' = {
  name: aksClusterName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: 'diaksdevcc01'
    agentPoolProfiles: [
      {
        name: 'system'
        count: 1
        vmSize: 'Standard_D4ds_v5'
        osType: 'Linux'
        type: 'VirtualMachineScaleSets'
        mode: 'System'
        vnetSubnetID: subnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: 3
      }
      {
        name: 'raynodepool'
        count: 1
        vmSize: 'Standard_D16d_v5'
        osType: 'Linux'
        type: 'VirtualMachineScaleSets'
        mode: 'User'
        vnetSubnetID: subnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: 10
        nodeTaints: [
          'sku=ray:NoSchedule'
        ]
        nodeLabels: {
          purpose: 'ray-head'
        } 
      }
      {
        name: 'gpunodepool'
        count: 1
        vmSize: 'Standard_NC96ads_A100_v4'
        osType: 'Linux'
        type: 'VirtualMachineScaleSets'
        mode: 'User'
        vnetSubnetID: subnetId
        enableAutoScaling: true
        minCount: 1
        maxCount: 5
        nodeTaints: [
          'sku=gpu:NoSchedule'
        ]
        nodeLabels: {
          purpose: 'gpu'
        }
      }
    ]
    networkProfile: {
      networkPlugin: 'azure'
      networkPolicy: 'azure'
      serviceCidr: '10.1.0.0/16'
      dnsServiceIP: '10.1.0.10'
    }
  }
}
