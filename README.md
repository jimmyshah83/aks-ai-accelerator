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