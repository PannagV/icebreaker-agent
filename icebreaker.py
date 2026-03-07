"""
ICEBREAKER v3 — Autonomous Pentesting Agent
Planner → Executor → Reflector + Exploit Retrieval

Run:
    python icebreaker_agent.py
"""

import json
import re
import shlex
import traceback
from datetime import datetime
from collections import deque

import paramiko
import faiss
import numpy as np

from openai import OpenAI
from sentence_transformers import SentenceTransformer



# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

ATTACK_MEMORY_FILE = "attack_memory.json"

LM_STUDIO_URL = "http://localhost:1234/v1"
LM_STUDIO_KEY = "lm-studio"
LM_MODEL = "local-model"

VM_IP = "192.168.31.12"
VM_USER = "kali"
VM_PASSWORD = "kali"

MAX_AUTO_STEPS = 30
MAX_OUTPUT_CHARS = 3000
COMMAND_TIMEOUT = 300

MAX_HISTORY = 20
MAX_LOG_ENTRIES = 200


# ─────────────────────────────────────────────
# VECTOR RETRIEVAL (Exploit Knowledge)
# ─────────────────────────────────────────────
import os

def load_attack_memory():

    if not os.path.exists(ATTACK_MEMORY_FILE):
        return []

    with open(ATTACK_MEMORY_FILE, "r") as f:
        return json.load(f)


def save_attack_memory(memory):

    with open(ATTACK_MEMORY_FILE, "w") as f:
        json.dump(memory, f, indent=2)


attack_memory = load_attack_memory()

def store_attack_chain(target, steps):

    entry = {
        "target": target,
        "steps": steps,
        "timestamp": datetime.now().isoformat()
    }

    attack_memory.append(entry)

    save_attack_memory(attack_memory)
    
EXPLOIT_INDEX_FILE = "exploit_index.faiss"
EXPLOIT_DOCS_FILE = "exploit_docs.json"

_embed_model = None
_faiss_index = None
_exploit_docs = None


def _load_exploit_retrieval():
    global _embed_model, _faiss_index, _exploit_docs

    if _faiss_index is not None:
        return True

    if not os.path.exists(EXPLOIT_INDEX_FILE) or not os.path.exists(EXPLOIT_DOCS_FILE):
        print(f"[!] Exploit retrieval files not found ({EXPLOIT_INDEX_FILE}, {EXPLOIT_DOCS_FILE}). Retrieval disabled.")
        return False

    print("[*] Loading exploit retrieval system...")
    _embed_model = SentenceTransformer("all-MiniLM-L6-v2")
    _faiss_index = faiss.read_index(EXPLOIT_INDEX_FILE)

    with open(EXPLOIT_DOCS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        _exploit_docs = data["docs"]

    print(f"[*] Loaded {len(_exploit_docs)} exploit documents.")
    return True


def retrieve_exploits(query, k=3):

    if not _load_exploit_retrieval():
        return "[No exploit knowledge available]"

    emb = _embed_model.encode([query])
    emb = np.array(emb).astype("float32")

    D, I = _faiss_index.search(emb, k)

    results = []

    for idx in I[0]:
        results.append(_exploit_docs[idx][:1500])

    return "\n\n".join(results)

def retrieve_attack_chain(target):

    results = []

    for entry in attack_memory:
        if target.lower() in entry["target"].lower():
            results.append(entry["steps"])

    if not results:
        return None

    return results[-1]


# ─────────────────────────────────────────────
# SYSTEM PROMPTS
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """
You are ICEBREAKER, an autonomous penetration testing AI.

Follow a structured pentesting workflow:

1. Discovery
2. Enumeration
3. Exploitation
4. Privilege escalation
5. Post-exploitation

Avoid repeating failed commands.
Always adapt based on results.
"""

PLANNER_PROMPT = """
You are the planning module for an autonomous pentesting AI.

Given the mission log and target, produce a concise attack plan.

Format:

PLAN:
1.
2.
3.
"""

REFLECTION_PROMPT = """
You are the reflection module.

Analyze the previous tool output.

Determine:
• Did the command succeed?
• Did it reveal useful findings?
• What should be attempted next?
"""


# ─────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────

TOOLS = [
{
"type":"function",
"function":{
"name":"execute_bash",
"description":"Execute bash command on Kali VM",
"parameters":{
"type":"object",
"properties":{"command":{"type":"string"}},
"required":["command"]
}}},

{
"type":"function",
"function":{
"name":"update_mission_log",
"description":"Store findings",
"parameters":{
"type":"object",
"properties":{
"section":{
"type":"string",
"enum":["hosts","open_ports","services","vulnerabilities","credentials","flags","notes"]
},
"entry":{"type":"string"}
},
"required":["section","entry"]
}}},

{
"type":"function",
"function":{
"name":"mission_complete",
"description":"Finish engagement",
"parameters":{
"type":"object",
"properties":{"summary":{"type":"string"}},
"required":["summary"]
}}}
]


# ─────────────────────────────────────────────
# SSH EXECUTION
# ─────────────────────────────────────────────

def ssh_connect():

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(
        hostname=VM_IP,
        username=VM_USER,
        password=VM_PASSWORD,
        timeout=10,
        look_for_keys=False,
        allow_agent=False
    )

    return ssh


def execute_bash(command):

    try:

        ssh = ssh_connect()

        try:
            if re.match(r"^\s*sudo\s", command):
                safe_pw = shlex.quote(VM_PASSWORD)
                command = f"echo {safe_pw} | sudo -S {re.sub(r'^\s*sudo\s+', '', command)}"

            stdin, stdout, stderr = ssh.exec_command(command)

            if hasattr(stdout, "channel"):
                stdout.channel.settimeout(COMMAND_TIMEOUT)

            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
        finally:
            ssh.close()

        result = (out + err).strip() or "[Success: no output]"

        if len(result) > MAX_OUTPUT_CHARS:
            result = result[:MAX_OUTPUT_CHARS] + "\n...[TRUNCATED]..."

        return result

    except Exception as e:
        return f"[SSH ERROR] {e}"


# ─────────────────────────────────────────────
# MISSION STATE
# ─────────────────────────────────────────────

class MissionState:

    def __init__(self):
        self.reset()

    def reset(self):

        self.log = {
        "hosts":[],
        "open_ports":[],
        "services":[],
        "vulnerabilities":[],
        "credentials":[],
        "flags":[],
        "notes":[]
        }

        self.step_count = 0
        self.running = False
        self.complete = False
        self.target = ""

        self.messages = []
        self.attack_steps = []
        self.last_commands = deque(maxlen=5)

    def update_log(self, section, entry):

        if section not in self.log:
            return "invalid log section"

        ts = datetime.now().strftime("%H:%M:%S")

        self.log[section].append(f"[{ts}] {entry}")

        if len(self.log[section]) > MAX_LOG_ENTRIES:
            self.log[section] = self.log[section][-MAX_LOG_ENTRIES:]

        return "log updated"


mission = MissionState()


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def dispatch_tool(name, args):

    if name == "execute_bash":

        cmd = args.get("command","")
        mission.attack_steps.append(cmd)

        if cmd in mission.last_commands:
            return "[duplicate command prevented]"

        mission.last_commands.append(cmd)

        return execute_bash(cmd)

    elif name == "update_mission_log":

        return mission.update_log(
            args.get("section","notes"),
            args.get("entry","")
        )

    elif name == "mission_complete":

        mission.complete = True
        store_attack_chain(mission.target, mission.attack_steps)
        return "mission complete"

    return "unknown tool"


# ─────────────────────────────────────────────
# PLANNER
# ─────────────────────────────────────────────

def generate_plan(client, task):

    resp = client.chat.completions.create(
        model=LM_MODEL,
        messages=[
            {"role":"system","content":PLANNER_PROMPT},
            {"role":"user","content":f"Target: {task}\n\nMission log:\n{json.dumps(mission.log,indent=2)}"}
        ],
        temperature=0.2
    )

    return resp.choices[0].message.content


# ─────────────────────────────────────────────
# REFLECTION
# ─────────────────────────────────────────────

def reflect(client, tool_output):

    resp = client.chat.completions.create(
        model=LM_MODEL,
        messages=[
            {"role":"system","content":REFLECTION_PROMPT},
            {"role":"user","content":tool_output}
        ],
        temperature=0.2
    )

    return resp.choices[0].message.content


# ─────────────────────────────────────────────
# AGENT LOOP
# ─────────────────────────────────────────────

def run_agent(task):

    mission.reset()
    mission.running = True
    mission.target = task

    mission.messages = [
        {"role":"system","content":SYSTEM_PROMPT},
        {"role":"user","content":task}
    ]

    # Inject exploit knowledge
    context = retrieve_exploits(task)

    mission.messages.insert(
        1,
        {
            "role":"system",
            "content":f"Relevant exploit knowledge:\n{context}"
        }
    )
    chain = retrieve_attack_chain(task)

    if chain:
        mission.messages.insert(
            2,
            {
                "role":"system",
                "content":f"Previous successful attack chain:\n{chain}"
            }
        )

    client = OpenAI(base_url=LM_STUDIO_URL, api_key=LM_STUDIO_KEY)

    plan = generate_plan(client, task)

    print("\nPLAN:\n", plan)

    while mission.running and mission.step_count < MAX_AUTO_STEPS:

        mission.step_count += 1

        try:

            response = client.chat.completions.create(
                model=LM_MODEL,
                messages=mission.messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.1
            )

            msg = response.choices[0].message
            mission.messages.append(msg)

            if len(mission.messages) > MAX_HISTORY:
                mission.messages = [mission.messages[0]] + mission.messages[-MAX_HISTORY:]

            if not msg.tool_calls:
                print(msg.content)
                break

            for tc in msg.tool_calls:

                try:
                    args = json.loads(tc.function.arguments or "{}")
                except (json.JSONDecodeError, TypeError) as e:
                    print(f"[!] Bad tool-call JSON from model: {e}")
                    args = {}

                tool_result = dispatch_tool(tc.function.name, args)

                print("\nTOOL:", tc.function.name)
                print(tool_result)

                mission.messages.append({
                    "role":"tool",
                    "tool_call_id":tc.id,
                    "name":tc.function.name,
                    "content":tool_result
                })

                reflection = reflect(client, tool_result)

                print("\nREFLECTION:\n", reflection)

                mission.messages.append({
                    "role":"assistant",
                    "content":reflection
                })

                if mission.complete:
                    mission.running = False
                    break

        except Exception:
            traceback.print_exc()
            break

    mission.running = False


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":

    print("""
ICEBREAKER v3
Autonomous Pentesting Agent
""")

    target = input("Enter target: ")

    run_agent(target)