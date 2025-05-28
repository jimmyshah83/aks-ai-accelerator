# Gen AI on AKS

- This is going to be built with maximum security. We will use Manged NGINX ingress controller with SSL termination fronted by App Gateway.
- Both inferencing and embedding API's would be exposed by API management.

NOTE:
To Deploy N series GPUs, one needs approval to enable N series on VMs. [See Here](https://dev.azure.com/OneCommercial/NoCode/_wiki/wikis/NoCode.wiki/37/Azure-Policy-Enforcement?anchor=vm-sku)
  
## Architecture use case

- Automated scaling of AKS cluster based on the load
- Resource management and cost optimization as compared to PTUs
- HA through Self-healing
- Edge computing with inferencing at the edge
- Secure and compliant with data residency requirements=
- Streamlined deployment and management
- Observability and monitoring
- Enable [mtls](https://techcommunity.microsoft.com/blog/azurepaasblog/mtls-between-aks-and-api-management/1813887) between APIM and NGINX can be implemented using
- install the Nvidia device plugin for kubernetes [k8s-device-plugin](https://github.com/NVIDIA/k8s-device-plugin?tab=readme-ov-file)
- install KubeRay for distributed inference

- To view Dashboard:

`kubectl port-forward service/${RAYCLUSTER_NAME}-head-svc 8265:8265`


## STEPS to deploy

1. Create a resource group

```bash
az group create --name <your-resource-group-name> --location <your-location>
```

1. Create the infrastructure using bicep

```bash
az deployment group create --resource-group <your-resource-group-name> --template-file init.bicep
```

1. Connect to the AKS cluster

```bash
az aks get-credentials --resource-group <your-resource-group-name> --name <your-aks-cluster-name>
```

1. Install the Nvidia device plugin for Kubernetes

```bash
kubectl apply -f nvidia-device-plugin.yml
```

1. Install KubeRay for distributed inference

```bash
helm repo add kuberay https://ray-project.github.io/kuberay-helm/
helm repo update
# Install both CRDs and KubeRay operator v1.3.0.
helm install kuberay-operator kuberay/kuberay-operator --version 1.3.0
```

1. Deploy the LLM

```bash
kubectl apply -f raysvc-llama3-8b-A100.yaml
```

1. Test the deployment

`kubectl port-forward svc/<NAME> 8000`

```bash
$ curl http://localhost:8000/v1/chat/completions -H "Content-Type: application/json" -d '{
      "model": "meta-llama/Meta-Llama-3-8B-Instruct",
      "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Provide a brief sentence describing the Ray open-source project."}
      ],
      "temperature": 0.7
    }'
```