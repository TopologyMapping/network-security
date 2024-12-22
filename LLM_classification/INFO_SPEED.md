### How to use the LLM model in a distributed way (SPEED LAB)

The LLM model can be used on the following machines at SPEED LAB: gorgona[1-2-4-5-6-7-10]

To use the LLM model in a distributed way, you need to follow the steps below:

- Start the RPC server at some machine: ex: gorgona2

```cd /home/all_home/gabriel.cardoso/llama-cpp/build-rpc-cuda/bin/```
```./rpc-server -H <ip_rpc> -p <port_rpc>```

- Go to a machine with the model: ex: gorgona1

```cd /home/all_home/gabriel.cardoso/llama-cpp/build-rpc-cuda/bin/```
```./llama-server -m /home/all_home/gabriel.cardoso/.cache/gguf/Reflection-Llama-3.1-70B-Q4_K_S.gguf -c 8192 -ngl 99 --rpc <ip_rpc>:<port_rpc> --host <ip_host> --port <port_host>```

Then just pass the ip_host:port_host to the code.

Ensure that the model is in the path specified in the command above and correctly installed. Also, ensure that the RPC server is running and the machine is available to use the model.