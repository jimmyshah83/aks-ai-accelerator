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