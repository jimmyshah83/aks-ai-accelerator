#!/bin/bash

# Variables
RESOURCE_GROUP_NAME="rg-genai-accelerator-dev-cc-01"
AKS_CLUSTER_NAME="genai-cluster-dev-cc-01"
NODE_POOL_NAME="gpunp01"
VM_SIZE="Standard_NC24s_v3"
NODE_COUNT=3

# Create spot node pool
az aks nodepool add \
    --resource-group $RESOURCE_GROUP_NAME \
    --cluster-name $AKS_CLUSTER_NAME \
    --name $NODE_POOL_NAME \
    --node-count $NODE_COUNT \
    --node-vm-size $VM_SIZE \
    --node-taints sku=gpu:NoSchedule \
    --priority Spot \
    --labels purpose=llama-demo \
    --eviction-policy Delete