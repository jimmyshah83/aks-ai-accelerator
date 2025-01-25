## Gen AI on AKS

![Gen AI Architecture](./images/azure-ai.svg)

- This is going to be built with maximum security. We will use Manged NGINX ingress controller with SSL termination fronted by App Gateway. 
- Both inferencing and embedding API's would be exposed by API management.

#### Architecture use case
- Automated scaling of AKS cluster based on the load
- Resource management and cost optimization as compared to PTUs
- HA through Self-healing
- Edge computing with inferencing at the edge
- Secure and compliant with data residency requirements=
- Streamlined deployment and management
- Observability and monitoring

#### Steps for Infrastructure setup
3. Create a virtual network (/23 with 2 subnets (/24) for AKS and APIM and /27 for Bastion)
4. Create a Bastion host in the Bastion subnet
5. Create NSG to allow APIM deployment inbound connectivity
6. Associate the NSG with the app-subnet  
NOTE: there are a lot of NSG rule to be applied, as mentioned here: https://learn.microsoft.com/en-us/azure/api-management/api-management-using-with-vnet?tabs=stv2#configure-nsg-rules
7. Create APIM in external mode
8. Create AKS Automatic Cluster inside VNET  