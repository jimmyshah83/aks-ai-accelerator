#!/bin/bash

# Variables
RESOURCE_GROUP_NAME="rg-genai-accelerator-dev-cc-01"
AKS_CLUSTER_NAME="genai-cluster-dev-cc-01"
NODE_POOL_NAME="slmcpunp01"
VM_SIZE="Standard_D32d_v5"
NODE_COUNT=2

az aks nodepool add \
    --resource-group $RESOURCE_GROUP_NAME \
    --cluster-name $AKS_CLUSTER_NAME \
    --name $NODE_POOL_NAME \
    --node-count $NODE_COUNT \
    --node-vm-size $VM_SIZE \
    --node-taints sku=slm:NoSchedule \
    --labels purpose=slm