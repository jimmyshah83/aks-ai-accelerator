#!/bin/bash

# Variables
RESOURCE_GROUP_NAME="rg-genai-accelerator-dev-cc-01"
AKS_CLUSTER_NAME="genai-cluster-dev-cc-01"
NODE_POOL_NAME="raycpunp01"
VM_SIZE="Standard_D16d_v5"
NODE_COUNT=1

az aks nodepool add \
    --resource-group $RESOURCE_GROUP_NAME \
    --cluster-name $AKS_CLUSTER_NAME \
    --name $NODE_POOL_NAME \
    --node-count $NODE_COUNT \
    --node-vm-size $VM_SIZE \
    --node-taints sku=ray:NoSchedule \
    --labels purpose=ray-head