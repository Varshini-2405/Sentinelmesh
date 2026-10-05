# 🛡️ SentinelMesh — Security Guard for AI Agents

> **Functional prototype demonstrating AI-agent action interception and defense against prompt-injection-style hijacking.**

## 🚀 Live Prototype

🔗 **[Try SentinelMesh Live](https://sentinelmesh.streamlit.app/)**

No installation required to try the prototype.

### 🎬 Quick Demo

**🟢 Safe Demo**
User Request → AI Action → Task Scope Check → ALLOW

**🔴 Attack Demo**
Malicious Document → Tainted Session → Fake Trap → Risk 100 → BLOCK → Agent Locked

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
