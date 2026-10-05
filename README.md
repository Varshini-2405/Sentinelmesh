# 🛡️ SentinelMesh — Security Guard for AI Agents

> **Functional prototype demonstrating AI-agent action interception and defense against prompt-injection-style hijacking.**

---

## 🚨 Problem Statement

Autonomous AI agents executing tools (reading files, calling APIs, sending network requests) can be manipulated by hidden malicious instructions buried inside untrusted input documents (indirect prompt injection). When an agent ingests a compromised document, it may attempt unauthorized actions—such as accessing credential stores or exfiltrating sensitive internal data—without the user's explicit intent or knowledge.

---

## 🛡️ Solution

**SentinelMesh** acts as a real-time inline security proxy sitting directly between the **AI Agent** and its **Tool Execution Layer**. Every tool call requested by the agent is intercepted, evaluated against task intent boundaries and threat signals, and enforced *before* any real file access or network transfer occurs.

```
       +--------------+
       |  User Task   |
       +------+-------+
              |
              v
       +--------------+
       |   AI Agent   |
       +------+-------+
              | (Tool Call Request)
              v
+-------------+------------------------------------+
|               SENTINELMESH                       |
|  +-------------------+    +-------------------+  |
|  | Task Scope Check  |    | Taint Tracking    |  |
|  +---------+---------+    +---------+---------+  |
|            |                        |            |
|            v                        v            |
|       +----------------------------------+       |
|       |    Rule-Based Security Engine    |       |
|       +----------------+-----------------+       |
|                        |                         |
+------------------------|-------------------------+
                         |
           +-------------+-------------+
           |                           |
           v                           v
     [ ALLOWED ]                  [ BLOCKED ]
           |                           |
   Executes Tool               Action Denied
   & Returns Data              Agent Locked 🔒
                               SQLite Logged 🗄️
```

---

## ✨ Key Features

1. **Inline Tool Action Interceptor**: Intercepts `read_file` and `send_data` tool calls before execution occurs.
2. **Dynamic Task Scope Enforcement**: Verifies whether target resources match the explicit user task scope (e.g. `normal_report.txt`).
3. **Session Taint Tracking**: Detects when an agent ingests untrusted content containing prompt-injection payloads and flags the session context as `TAINTED`.
4. **Honeypot Decoy Traps**: Deploys fake credential files (`traps/fake_passwords.txt`, `fake_api_keys.txt`). Access attempts trigger an immediate mandatory hard **BLOCK & LOCK**.
5. **Transparent Scoring Risk Engine**: Transparent multi-signal risk scoring (0 to 100) with rule-based thresholds (`ALLOW`, `ASK USER`, `BLOCK`).
6. **SQLite Incident Audit Logging**: Logs all security events, intercepted tool parameters, risk scores, and decisions to a local SQLite database (`sentinelmesh.db`).
7. **Streamlit Cybersecurity Dashboard**: Real-time visualization featuring live action timelines, risk signal breakdowns, status indicators, and incident tables.

---

## 📊 Risk Scoring Engine Matrix

| Signal Criteria | Weight | Description |
| :--- | :---: | :--- |
| **Action Outside Task Scope** | `+35` | Tool targets a file outside explicit user intent |
| **Sensitive Resource Access** | `+20` | File contains passwords, keys, secrets, or system tokens |
| **Fake Honeypot Trap Touched** | `+50` | Agent attempts to access fake decoy credential files |
| **Session Context Tainted** | `+15` | Session previously ingested untrusted/malicious payload |
| **External Data Transfer** | `+25` | Agent attempts outbound exfiltration / send_data tool call |

### Decision Thresholds
- `0 - 30`: **ALLOW**
- `31 - 70`: **ASK USER**
- `71 - 100`: **BLOCK**

> ⚠️ **HARD RULE**: Accessing any honeypot trap (`traps/fake_passwords.txt`) immediately sets Risk Score = **100**, decision = **BLOCK**, and **LOCKS THE AGENT**.

---

## 🚀 Quick Start & Installation

### Prerequisites
- **Python**: 3.11 or higher
- **OS**: Windows, macOS, or Linux
- **No external paid API keys or cloud services required!** Works 100% offline.

### 1. Clone & Navigate
```bash
git clone https://github.com/your-org/sentinelmesh.git
cd sentinelmesh
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch Streamlit Dashboard
```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

---

## 🎬 How to Run the Demo

### Scenario 1: Normal Safe Task
1. Click **`▶ Run Safe Demo`** on the left sidebar.
2. User task: `"Summarize normal_report.txt"`.
3. Agent reads `normal_report.txt` (allowed within task scope).
4. **SentinelMesh Output**: `ALLOW` | **Risk Score**: `0 / 100` | **Status**: 🟢 `SAFE`.

### Scenario 2: Indirect Prompt Injection Attack
1. Click **`⚠ Run Attack Demo`** on the left sidebar.
2. User task: `"Summarize malicious_report.txt"`.
3. Agent ingests `malicious_report.txt` $\rightarrow$ Taint Tracker sets session status to ⚠️ `TAINTED`.
4. Injected instructions attempt to force the agent to execute `read_file("traps/fake_passwords.txt")`.
5. **SentinelMesh Interceptor** catches the action before execution.
6. Risk Engine calculates:
   - Outside Scope (`+35`) + Sensitive Resource (`+20`) + Fake Trap (`+50`) + Tainted Session (`+15`) = **120** $\rightarrow$ Capped at **100**.
7. **SentinelMesh Output**: 🚨 `THREAT DETECTED` | 🚫 `ACTION BLOCKED` | 🔒 `AGENT LOCKED`.
8. The fake credential file is **NEVER opened or exposed**.

---

## 📂 Project Structure

```
sentinelmesh/
│
├── app.py                      # Streamlit interactive cybersecurity dashboard
│
├── core/
│   ├── agent.py                # Mock AI Agent with interceptor tool routing
│   ├── security_engine.py      # Rule-based risk evaluation engine
│   ├── interceptor.py          # Action interceptor proxy
│   ├── taint_tracker.py        # Ingress content taint tracking module
│   ├── task_scope.py           # Task intent & resource scope manager
│   └── database.py             # SQLite incident database logger
│
├── traps/                      # Decoy Honeypot Data
│   ├── fake_passwords.txt
│   ├── fake_api_keys.txt
│   └── fake_company_secrets.txt
│
├── test_data/                  # Demo Test Documents
│   ├── normal_report.txt
│   └── malicious_report.txt
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🔮 Future Scope

- **LLM Intent Embeddings**: Incorporate semantic vector similarity to evaluate task scope dynamically for complex prompts.
- **DLP Payload Sanitization**: Automatic redaction of sensitive tokens in allowed outputs.
- **Multi-Agent Governance**: Standardized security proxy protocol (e.g. MCP proxy layer) for agent-to-agent communication networks.
