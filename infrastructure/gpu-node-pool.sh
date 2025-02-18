#!/bin/bash

# Variables
RESOURCE_GROUP_NAME="rg-genai-accelerator-dev-cc-01"
AKS_CLUSTER_NAME="genai-cluster-dev-cc-01"
NODE_POOL_NAME="gpunp01"
VM_SIZE="Standard_NC24s_v3"
NODE_COUNT=1
# VM_SIZE="Standard_NC96ads_A100_v4"
# NODE_COUNT=2

# To create spot node pool, use Spot as priority and enable eviction-policy
#  --priority Spot \
az aks nodepool add \
    --resource-group $RESOURCE_GROUP_NAME \
    --cluster-name $AKS_CLUSTER_NAME \
    --name $NODE_POOL_NAME \
    --node-count $NODE_COUNT \
    --node-vm-size $VM_SIZE \
    --node-taints sku=gpu:NoSchedule \
    --labels purpose=llama-demo \
    # --eviction-policy Delete