from ray import serve
from ray.serve.llm import LLMConfig, LLMServer, LLMRouter
import ray
import os
import sys

# Force using CPU by setting environment variables
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["RAY_DEDUP_LOGS"] = "0"

# Explicitly configure model to load on CPU
llm_config = LLMConfig(
    model_loading_config=dict(
        model_id="phi4-mini-instruct",
        model_source="microsoft/Phi-4-mini-instruct"
    ),
    deployment_config=dict(
        num_replicas=1,
        ray_actor_options={"num_cpus": 0.2, "num_gpus": 0},
    ),
    llm_engine="vLLM",
)

# Deploy the application with error handling
try:
    print("Starting model deployment...")
    deployment = LLMServer.as_deployment(llm_config.get_serve_options(name_prefix="CPU:")).bind(llm_config)
    llm_app = LLMRouter.as_deployment().bind([deployment])

    print("Starting Ray Serve...")
    serve.run(
        llm_app, 
        blocking=True,
    )
except Exception as e:
    print(f"Error during deployment: {e}")
    ray.shutdown()
    sys.exit(1)