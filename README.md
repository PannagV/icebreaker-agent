# Icebreaker Agent
Icebreaker is an open-source, autonomous penetration testing AI agent. Powered by a fine-tuned Qwen 2.5 7B model, it is designed to run entirely locally, bridging the gap between Large Language Model reasoning and active cybersecurity operations.

This repository contains the core Python agent script responsible for loading the model, managing the reasoning loop, and executing command-line tools autonomously.

## Features
100% Local Execution: Utilizes GGUF format for completely offline, air-gapped inference, ensuring sensitive target data never leaves your environment.

Autonomous Reasoning: Fine-tuned on CTF write-ups to think like an attacker, chain vulnerabilities, and strategize multi-step exploits.

Dynamic Tool Usage: Trained on ToolBench datasets to seamlessly format commands, execute standard offensive security tools (like Nmap, Metasploit, etc.), and parse their terminal outputs.

Extensible Architecture: Easily add custom tools or integrate with existing SIEM/SOC dashboards (like Heimdall) for automated adversary simulation.

## Prerequisites
Before running the agent, ensure you have the following installed:

Python 3.8+

A local LLM runner compatible with GGUF (e.g., LM Studio, llama.cpp or Ollama)
Download the model file from here: [pannagkv/icebreaker-v2](https://huggingface.co/pannagkv/icebreaker-v2)
Required offensive security tools installed locally and accessible via your system's PATH (e.g., nmap, msfconsole).

## Usage
To launch the interactive agent console, run the main script:

```bash
python icebreaker.py
```
Set the local server port and your IP address and the IP address of the VM (Kali VM) in the script before usage.

## Disclaimer
Strictly for educational and authorized testing purposes only. This tool is designed to assist security professionals in identifying and mitigating vulnerabilities within systems they own or have explicit, written permission to test. The developer assumes no liability and are not responsible for any misuse or damage caused by this program.
