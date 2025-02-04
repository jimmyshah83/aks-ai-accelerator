#!/bin/bash

# Variables
RESOURCE_GROUP="rg-genai-accelerator-dev-cc-01"
CLUSTER_NAME="genai-cluster-dev-cc-01"
NODE_POOL_NAME="gpunp01"
NODE_VM_SIZE="Standard_NC6s_v3"
NODE_COUNT=2

# Create a GPU node pool in the AKS cluster
az aks nodepool add \
    --resource-group $RESOURCE_GROUP \
    --cluster-name $CLUSTER_NAME \
    --name $NODE_POOL_NAME \
    --node-vm-size $NODE_VM_SIZE \
    --node-count $NODE_COUNT \
    --enable-cluster-autoscaler \
    --min-count 2 \
    --max-count 4 \
    --node-taints sku=gpu:NoSchedule