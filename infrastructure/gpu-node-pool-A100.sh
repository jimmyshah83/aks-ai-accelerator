#!/bin/bash

# Variables
RESOURCE_GROUP_NAME="rg-genai-accelerator-dev-cc-01"
AKS_CLUSTER_NAME="genai-cluster-dev-cc-01"
NODE_POOL_NAME="gpunp01"
NODE_COUNT=1
VM_SIZE="Standard_NC96ads_A100_v4"
# VM_SIZE="Standard_NC24s_v3"

# To disable spot node pool, remove Spot as priority and enable eviction-policy
az aks nodepool add \
    --resource-group $RESOURCE_GROUP_NAME \
    --cluster-name $AKS_CLUSTER_NAME \
    --name $NODE_POOL_NAME \
    --node-count $NODE_COUNT \
    --node-vm-size $VM_SIZE \
    --node-taints sku=gpu:NoSchedule \
    --labels purpose=llm-rayserve \
    # --priority Spot \
    # --eviction-policy Delete