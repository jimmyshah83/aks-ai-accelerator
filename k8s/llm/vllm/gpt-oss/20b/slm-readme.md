# SLM (Small Language Model) Deployment with vLLM

## Overview

This folder contains Kubernetes deployment configurations for running the GPT-OSS 20B model using vLLM on CPU-optimized nodes in Azure Kubernetes Service (AKS).

## Current Configuration

The deployment (`vllm-deployment.yaml`) attempts to use the pre-built vLLM Docker image (`vllm/vllm-openai:latest`) with CPU inference for the GPT-OSS 20B model.

### Key Features:
- **Node Selection**: Targets SLM-dedicated nodes with `purpose: slm` label
- **Tolerations**: Handles `sku=slm` taints for proper scheduling
- **CPU Optimization**: Uses `--device-type cpu` for CPU-based inference
- **Resource Allocation**: 27 CPU cores and 50Gi memory
- **AVX512F Support**: The target node (`aks-slmcpunp01-27011442-vmss000000`) supports AVX512F instructions

## ❌ Why This Solution Won't Work

**Problem**: The pre-built vLLM Docker images (`vllm/vllm-openai:latest`) do not include optimized wheels or binaries for CPU inference on x86_64 architectures with AVX512F support.

### Issues:
1. **Missing CPU Optimizations**: Pre-built images lack CPU-specific optimizations
2. **No AVX512F Binaries**: The images don't contain binaries compiled with AVX512F support
3. **Suboptimal Performance**: Without proper CPU optimizations, inference will be significantly slower
4. **Compatibility Issues**: May encounter runtime errors or fallback to unoptimized code paths

## ✅ Solution: Build vLLM from Source

To properly leverage the AVX512F capabilities of the Intel Xeon Platinum 8370C processors, vLLM must be built from source with CPU-specific optimizations.

### Build Requirements:
- Build vLLM with CPU optimizations enabled
- Compile with AVX512F instruction set support
- Create custom Docker image with optimized binaries

### Reference Documentation:
📚 **vLLM CPU Installation Guide**: https://docs.vllm.ai/en/v0.7.3/getting_started/installation/cpu/index.html?device=x86

### Next Steps:
1. **Create Custom Dockerfile**: Build vLLM from source with CPU optimizations
2. **Enable AVX512F**: Ensure build flags include AVX512F support
3. **Build and Push Image**: Create optimized Docker image for your container registry
4. **Update Deployment**: Modify `vllm-deployment.yaml` to use the custom image

### Example Build Commands:
```bash
# Clone vLLM repository
git clone https://github.com/vllm-project/vllm.git
cd vllm

# Build with CPU optimizations
export VLLM_TARGET_DEVICE=cpu
export CMAKE_ARGS="-DVLLM_CPU_AVX512BF16=ON"
pip install -e .
```

## Hardware Specifications

### Target Node: `aks-slmcpunp01-27011442-vmss000000`
- **CPU**: Intel(R) Xeon(R) Platinum 8370C @ 2.80GHz
- **Cores**: 16 physical cores (32 with hyperthreading)
- **Architecture**: x86_64
- **AVX512F Support**: ✅ Confirmed
- **Memory**: 50Gi allocated for the workload

### Supported AVX512 Extensions:
- `avx512f` (Foundation)
- `avx512dq` (Doubleword and Quadword)
- `avx512cd` (Conflict Detection)
- `avx512bw` (Byte and Word)
- `avx512vl` (Vector Length)
- `avx512ifma` (Integer Fused Multiply-Add)
- `avx512vbmi` (Vector Bit Manipulation Instructions)
- `avx512vnni` (Vector Neural Network Instructions)

## Performance Expectations

With proper CPU optimizations and AVX512F support:
- **Faster Inference**: Significant performance improvement over unoptimized builds
- **Better Throughput**: Efficient utilization of wide vector instructions
- **Lower Latency**: Optimized matrix operations for transformer models
- **Resource Efficiency**: Better CPU utilization and memory bandwidth

## Environment Configuration

The deployment includes optimized environment variables:
- `VLLM_CPU_KVCACHE_SPACE=8`: Allocates 8GB for KV cache
- `VLLM_LOGGING_LEVEL=DEBUG`: Enables detailed logging for troubleshooting
- `CUDA_VISIBLE_DEVICES=""`: Ensures CPU-only operation

## Model Configuration

Current model settings:
- **Model**: `openai/gpt-oss-20b`
- **Data Type**: `float16` for memory efficiency
- **Max Length**: `2048` tokens
- **Eager Mode**: `--enforce-eager` for consistent CPU execution

---

**Note**: This README documents the current state and required improvements. The deployment will need to be updated with a custom-built vLLM image to achieve optimal performance on the available hardware.
