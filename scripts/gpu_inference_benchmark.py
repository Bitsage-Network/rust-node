#!/usr/bin/env python3
"""Real GPU AI Inference Benchmark on H100"""

import torch
import torch.nn as nn
import time

print("=" * 72)
print("        REAL GPU AI INFERENCE BENCHMARK - H100")
print("=" * 72)
print()

# Check GPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {device}")
if torch.cuda.is_available():
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
print()

# Create a realistic ML model (transformer-like)
class MLInferenceModel(nn.Module):
    def __init__(self, input_dim=512, hidden_dim=2048, num_layers=6):
        super().__init__()
        layers = []
        for i in range(num_layers):
            in_d = input_dim if i == 0 else hidden_dim
            layers.extend([
                nn.Linear(in_d, hidden_dim),
                nn.LayerNorm(hidden_dim),
                nn.GELU(),
            ])
        layers.append(nn.Linear(hidden_dim, 256))  # Output layer
        self.model = nn.Sequential(*layers)

    def forward(self, x):
        return self.model(x)

# Initialize model on GPU
model = MLInferenceModel().to(device)
model.eval()

print(f"Model Parameters: {sum(p.numel() for p in model.parameters()):,}")
print()

# Warmup
with torch.no_grad():
    dummy = torch.randn(1, 512, device=device)
    _ = model(dummy)
    torch.cuda.synchronize()

# Benchmark different batch sizes
print("-" * 72)
print("INFERENCE BENCHMARK (varying batch sizes)")
print("-" * 72)
print(f"{'Batch Size':>12} | {'Inferences':>12} | {'Time (ms)':>12} | {'Throughput':>15}")
print("-" * 60)

total_inferences = 0
total_time = 0

for batch_size in [1, 10, 100, 1000, 10000]:
    num_batches = max(1, 10000 // batch_size)

    # Create input batch
    inputs = torch.randn(batch_size, 512, device=device)

    # Measure inference time
    torch.cuda.synchronize()
    start = time.perf_counter()

    with torch.no_grad():
        for _ in range(num_batches):
            outputs = model(inputs)

    torch.cuda.synchronize()
    elapsed = (time.perf_counter() - start) * 1000  # ms

    total_inferences += batch_size * num_batches
    total_time += elapsed

    throughput = (batch_size * num_batches) / (elapsed / 1000)
    print(f"{batch_size:>12,} | {batch_size * num_batches:>12,} | {elapsed:>12.2f} | {throughput:>12,.0f}/sec")

print()
print("-" * 72)
print("LARGE-SCALE BATCH (Simulating 100,000 ML inferences)")
print("-" * 72)

num_total = 100000
batch_size = 10000
num_batches = num_total // batch_size

inputs = torch.randn(batch_size, 512, device=device)

torch.cuda.synchronize()
start = time.perf_counter()

with torch.no_grad():
    for _ in range(num_batches):
        outputs = model(inputs)
        # Extract output hash (simulating proof commitment)
        output_hash = outputs.sum().item()

torch.cuda.synchronize()
elapsed = time.perf_counter() - start

print(f"  Total inferences:    {num_total:,}")
print(f"  Total time:          {elapsed:.3f}s")
print(f"  Throughput:          {num_total / elapsed:,.0f} inferences/sec")
print(f"  Time per inference:  {elapsed * 1000 / num_total:.4f}ms")
print()
print(f"  GPU Memory Used:     {torch.cuda.max_memory_allocated() / 1e9:.2f} GB")
print()

# CPU comparison
print("-" * 72)
print("CPU vs GPU COMPARISON (10,000 inferences)")
print("-" * 72)

# Move model to CPU for comparison
model_cpu = MLInferenceModel().cpu()
model_cpu.eval()

inputs_cpu = torch.randn(1000, 512)

start_cpu = time.perf_counter()
with torch.no_grad():
    for _ in range(10):  # 10 batches of 1000 = 10,000 inferences
        _ = model_cpu(inputs_cpu)
elapsed_cpu = time.perf_counter() - start_cpu
cpu_throughput = 10000 / elapsed_cpu

inputs_gpu = torch.randn(1000, 512, device=device)
torch.cuda.synchronize()
start_gpu = time.perf_counter()
with torch.no_grad():
    for _ in range(10):
        _ = model(inputs_gpu)
torch.cuda.synchronize()
elapsed_gpu = time.perf_counter() - start_gpu
gpu_throughput = 10000 / elapsed_gpu

speedup = gpu_throughput / cpu_throughput
print(f"  CPU throughput:      {cpu_throughput:,.0f} inferences/sec")
print(f"  GPU throughput:      {gpu_throughput:,.0f} inferences/sec")
print(f"  GPU SPEEDUP:         {speedup:.1f}x faster")
print()
print("=" * 72)
