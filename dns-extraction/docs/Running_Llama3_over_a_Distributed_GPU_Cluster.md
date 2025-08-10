# Running Llama 3 over a Distributed GPU Cluster

This guide explains how to run Llama 3 on a distributed cluster of machines. The machine hosting the model exposes a port that can be interacted with using the OpenAI API from any other machine on the same network.

This setup is designed for a cluster of machines equipped with CUDA-compatible NVIDIA GPUs. The instructions are general but were tested on machines with NVIDIA RTX 4090 and RTX 3090 Ti GPUs.

## Setup overview

We use [llama-cpp](https://github.com/ggerganov/llama.cpp) as a framework to run the models. Once set up, the framework consists of:

- **One host machine.** Has the model downloaded and exposes a port for interaction using the OpenAI API.
- **Zero or more RPC machines.** Expose a port for interaction with the host machine, thus allowing for distributed inference. They do not need the model file.
- **One client machine,** can be any of the above or a different one. Interacts with the host machine using the OpenAI API, sends prompts to be evaluated, and can send multiple prompts sequentially.

## Setting up

### Build tools

llama-cpp needs to be compiled from scratch to better suit the machine it will run, which includes support for CUDA and RPC.

We use Anaconda for consistency and to eliminate any possible differences between build environments.

To get started, connect to one of the machines in your cluster. Your cluster might use a module system to manage software environments. If so, load the appropriate Anaconda/Miniconda module. The command might look like this:

```bash
module load anaconda3/2023.09
```
Check if `conda` is available by running:
    
```Bash
conda --version
```

If set up correctly, this should print a version number, for example: `conda 23.7.4`.

Create and activate a conda environment (replace `~/path/to/your/env` with your desired location):

```Bash
conda create --prefix ~/path/to/your/env
conda activate ~/path/to/your/env
```

*NOTE: You can deactivate a conda environment by running `conda deactivate`, but you will need to activate the environment every time you want to run the model, since all build dependencies and shared libraries are part of the environment.*

For compilation, we need `gcc`, `g++` and `nvcc` (Nvidia CUDA compiler), as well as the CUDA shared libraries. Thankfully, we can install all of this using `conda`.

Check available `cuda-toolkit` versions:

```Bash
conda search cuda-toolkit
```

Sample output:

```txt
Loading channels: done
# Name                       Version           Build  Channel
cuda-toolkit                  12.0.0      h7428d3b_0  conda-forge
```

Install any version above 12.0. For reference, we have tested the following steps with version 12.0.

```Bash
conda install cuda-toolkit=12.0
```

More details about using Anaconda to manage dependencies are available in the [official Conda documentation](https://www.google.com/search?q=https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-dependencies.html).

### Compiling llama-cpp

After setting up the conda environment as described above, head over to [llama-cpp on GitHub](https://github.com/ggerganov/llama-cpp) and clone the repository.
    
After cloning, `cd` into the `llama-cpp` directory and execute the following commands one at a time:

```Bash
mkdir build-rpc-cuda
cd build-rpc-cuda
cmake .. -DGGML_CUDA=ON -DGGML_RPC=ON
cmake --build . --config Release
```

*NOTE: These compilation instructions were taken directly from the llama-cpp docs and are subject to change.*

After the first `cmake`, check if the CUDA environment is being recognized and if CUDA and RPC support are included in the build:
    
```
-- Found CUDAToolkit: /path/to/targets/x86_64-linux/include (found version "12.0.76")
-- CUDA Toolkit found

...

-- Including CUDA backend
-- Using RPC backend
-- Including RPC backend
-- Configuring done
-- Generating done
-- Build files have been written to: /path/to/llama-cpp/build-rpc-cuda
```

The second `cmake` will compile llama-cpp. This process will take a while.

Check if CUDA source files build successfully:

```txt
[  8%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/acc.cu.o
[  9%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/arange.cu.o
[  9%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/argmax.cu.o
[ 10%] Building CUDA object ggml/src/ggml-cuda/CMakeFiles/ggml-cuda.dir/argsort.cu.o
```

After compilation, all binaries will be inside the `llama-cpp/build-rpc-cuda/bin` folder. **Repeat this compilation process for every machine in the cluster you intend to use.**

### Downloading a suitable model file

The model files for `llama-cpp` are `.gguf` files (GPT-Generated Unified Format). You can download these models from Hugging Face. We recommend using quantized models, which are compressed versions suitable for systems with less VRAM.

For example, you can find Llama 3 models on the [meta-llama Hugging Face page](https://huggingface.co/meta-llama). We recommend using `huggingface-cli` for downloads.

Specifically, we have used:

- Reflection-Llama-3.1-70B-Q4_K_S (40 GB, needs 2 machines)
- Reflection-Llama-3.1-70B-Q6_K_L (59 GB, needs 3 machines)

The model size directly determines how many machines you'll need. As an example, if your GPUs have 24 GB of VRAM (of which ~2 GB may be used by the CUDA kernel), this means about 22 GB is available per machine:

- A **40 GB** model would need **2 machines** (1 host, 1 RPC server).
- A **59 GB** model would need **3 machines** (1 host, 2 RPC servers).
    
The model should be downloaded to just one machine; this machine will be the **host**.

## Running the model

After setting up `llama-cpp` for every machine and downloading a suitable `.gguf` file, three steps remain. Navigate to the binaries folder: `cd llama-cpp/build-rpc-cuda/bin`. Every command below is run from this folder.

### 1. Running RPC servers (RPC machines)

First, set up the necessary amount of RPC servers, ensuring enough total VRAM to fit the model. Note that the machines must be able to communicate with each other over the network (e.g., be on the same LAN or VLAN).
    
Run the following command on each RPC machine:

```Bash
./rpc-server -H <rpc_ip> -p <port>
```

Replace `<rpc_ip>` with the IP address of the RPC machine and `<port>` with a free port of your choice. For example, if your RPC machine's IP is `192.168.1.101` and you choose port `50052`:

```Bash
./rpc-server -H 192.168.1.101 -p 50052
```

Check if the GPU is recognized and if the server started successfully:

```Bash
create_backend: using CUDA backend
ggml_cuda_init: GGML_CUDA_FORCE_MMQ:    no
ggml_cuda_init: GGML_CUDA_FORCE_CUBLAS: no
ggml_cuda_init: found 1 CUDA devices:
  Device 0: NVIDIA GeForce RTX 3090 Ti, compute capability 8.6, VMM: yes
Starting RPC server on 192.168.1.101:50052, backend memory: 23972 MB
```

*NOTE: If the line "Starting RPC server..." does not show, the server hasn't started. Check if the port you chose is available. In rare cases, the server takes a few minutes to start. If it fails, end the process and try again.*

Repeat this process for as many RPC servers as you need. Leave them running and proceed to the next step.

### 2. Running host server (host machine)

On the host machine (the one with the `.gguf` file), run `llama-server`:

```Bash
./llama-server -m /path/to/model.gguf -c 8192 -ngl 99 --rpc <rpc_ip1>:<port1>,<rpc_ip2>:<port2> --host <server_ip> --port <server_port>
```
Where:

- `/path/to/model.gguf` is your model file.
- `<rpc_ip>:<port>` is the IP and port of a running RPC server. Separate multiple RPC servers with a comma.
- `<server_ip>` and `<server_port>` are the IP and a free port for the host machine. The client will connect to this address.
- `-ngl 99` indicates how many layers of the model should run on the GPUs.
- `-c 8192` indicates the context window size. Larger contexts require more VRAM.
    
For example, to run the host on a machine with IP `192.168.1.100` and connect to an RPC server at `192.168.1.101:50052`:

```Bash
./llama-server -m /path/to/your/model.gguf -c 8192 -ngl 99 --rpc 192.168.1.101:50052 --host 192.168.1.100 --port 50001
```

Check the log to ensure the RPC servers are connected and the server is listening:

```
llm_load_tensors: RPC[192.168.1.101:50052] buffer size = 19142.56 MiB
...
main: server is listening on 192.168.1.100:50001 - starting the main loop
```

Leave the server running and proceed to the final step.

### 3. Running client (client machine)

From any machine on the network, you can connect to the host server with Python to send prompts.

First, install the OpenAI client library:

```Bash
pip install openai
```

Then, use this sample Python code:

```Python
import openai

# Replace with your host IP and port
HOST_IP = "192.168.1.100"
HOST_PORT = "50001"

system_prompt = "You are a helpful assistant."
user_prompt = "Explain the importance of distributed computing."

llm = openai.OpenAI(
    base_url=f"http://{HOST_IP}:{HOST_PORT}/v1",
    api_key="sk-no-key-required"
)

out = llm.chat.completions.create(
    model="llama-3", # Model name can be anything
    messages=[
        {
            "role": "system",
            "content": f"{system_prompt}"
        },
        {
            "role": "user",
            "content": f"{user_prompt}"
        }
    ],
    max_tokens=None
)

print(out.choices[0].message.content)
```

## Appendix

### Finding Your Machine's IP Address

To find the local IP address of a machine on a Linux-based system, you can use commands like `hostname -I` or `ip addr show`. The exact command may vary depending on your network configuration and operating system.