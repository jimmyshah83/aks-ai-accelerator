# Gen AI on AKS

![Gen AI Architecture](./images/arch.svg)

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

<!-- 
To use vLLM on multiple nodes, you need to start ray on all nodes and set the environment variable on all nodes.

The steps are:

start ray on the Head Node
 ray start --head --port 6379
start ray the other nodes
ray start --address="head_node_IP:6379"
Set the envrionment on all nodes
Download model on all node and the same path, of course you download on the fly
start vLLM on anynode with tensor_parallel_size=$GPU_COUNT --engine-use-ray
-->


<!-- Infrastructure setup -->

<!-- Virtual Network Create a virtual network (/23 with 2 subnets (/24) for AKS and APIM and /27 for Bastion) -->
<!-- Create a Bastion host in the Bastion subnet -->
<!-- Create NSG to allow APIM deployment inbound connectivity -->
<!-- Associate the NSG with the app-subnet  NOTE: there are a lot of NSG rule to be applied, as mentioned here: https://learn.microsoft.com/en-us/azure/api-management/api-management-using-with-vnet?tabs=stv2#configure-nsg-rules -->
<!-- Create APIM in external mode -->
<!-- Create AKS Cluster inside VNET   -->
<!-- Create AI Search (Basic) with Private endpoint -->
<!-- storage account instance with Private endpoint -->
<!-- 
    Configure NGINX ingress controller to support Azure private DNS zone with application routing add-on https://learn.microsoft.com/en-us/azure/aks/create-nginx-ingress-private-controller 

    The application routing add-on with NGINX delivers the following:
        Easy configuration of managed NGINX Ingress controllers based on Kubernetes NGINX Ingress controller.
        Integration with Azure DNS for public and private zone management
        SSL termination with certificates stored in Azure Key Vault.
-->
<!-- 
    Monitoring 
        https://learn.microsoft.com/en-us/azure/aks/app-routing-nginx-prometheus
-->
<!-- 
    Security
        Self Signed certs for mutual TLS
-->
- To view Dashboard:

`kubectl port-forward service/${RAYCLUSTER_NAME}-head-svc 8265:8265`

- Test the deployment

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