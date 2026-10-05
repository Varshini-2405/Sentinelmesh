import streamlit as st
import os
import uuid
from datetime import datetime
import pandas as pd

from core.task_scope import TaskScope
from core.taint_tracker import TaintTracker
from core.security_engine import SecurityEngine
from core.interceptor import Interceptor
from core.agent import MockAgent
from core import database

# -------------------------------------------------------------------
# Page Config & Custom Styling
# -------------------------------------------------------------------
st.set_page_config(
    page_title="SentinelMesh | AI Security Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cybersecurity Dashboard Aesthetic
st.markdown("""
<style>
    /* Dark Cybersecurity Theme Colors */
    :root {
        --bg-color: #0b0f19;
        --card-bg: #131b2e;
        --border-color: #1e2d4a;
        --accent-green: #00e676;
        --accent-red: #ff1744;
        --accent-yellow: #ffc400;
        --accent-blue: #29b6f6;
        --text-primary: #e2e8f0;
    }
    
    .stApp {
        background-color: var(--bg-color);
        color: var(--text-primary);
    }
    
    /* Card Component */
    .sec-card {
        background-color: #131b2e;
        border: 1px solid #1e2d4a;
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    
    /* Metric Card Styling */
    .metric-card {
        background-color: #131b2e;
        border: 1px solid #1e2d4a;
        border-radius: 10px;
        padding: 16px 20px;
        text-align: center;
        box-shadow: 0 4px 15px rgba(0,0,0,0.25);
    }
    .metric-card-title {
        font-size: 0.75rem;
        font-weight: 700;
        color: #94a3b8;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 10px;
    }
    .metric-card-value {
        font-size: 2.2rem;
        font-weight: 800;
        line-height: 1.1;
    }

    /* Badges & Status Indicators */
    .badge-safe {
        background-color: rgba(0, 230, 118, 0.15);
        color: #00e676;
        border: 1px solid #00e676;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.95rem;
        display: inline-block;
    }
    
    .badge-blocked {
        background-color: rgba(255, 23, 68, 0.15);
        color: #ff1744;
        border: 1px solid #ff1744;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.95rem;
        display: inline-block;
    }
    
    .badge-tainted {
        background-color: rgba(255, 196, 0, 0.15);
        color: #ffc400;
        border: 1px solid #ffc400;
        padding: 5px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 0.95rem;
        display: inline-block;
    }

    /* Threat Alert Banner */
    .threat-banner {
        background: linear-gradient(135deg, rgba(255, 23, 68, 0.22) 0%, rgba(136, 14, 79, 0.38) 100%);
        border: 2px solid #ff1744;
        border-radius: 12px;
        padding: 24px;
        margin-top: 15px;
        margin-bottom: 25px;
        text-align: center;
        box-shadow: 0 0 30px rgba(255, 23, 68, 0.3);
    }
    
    .threat-banner h2 {
        color: #ff1744;
        margin-bottom: 8px;
        font-size: 1.75rem;
        font-weight: 800;
        letter-spacing: 1px;
    }
    
    .safe-banner {
        background: linear-gradient(135deg, rgba(0, 230, 118, 0.15) 0%, rgba(27, 94, 32, 0.3) 100%);
        border: 1.5px solid #00e676;
        border-radius: 12px;
        padding: 18px;
        margin-top: 15px;
        margin-bottom: 25px;
        text-align: center;
    }

    /* Timeline step node */
    .timeline-node {
        border-left: 3px solid #29b6f6;
        padding-left: 15px;
        margin-bottom: 14px;
    }
    
    .timeline-node-blocked {
        border-left: 3px solid #ff1744;
        padding-left: 15px;
        margin-bottom: 14px;
        background: rgba(255, 23, 68, 0.05);
        border-radius: 0 8px 8px 0;
    }

    .timeline-node-tainted {
        border-left: 3px solid #ffc400;
        padding-left: 15px;
        margin-bottom: 14px;
        background: rgba(255, 196, 0, 0.05);
        border-radius: 0 8px 8px 0;
    }

    /* Step Card for 'How SentinelMesh Stopped It' */
    .step-box {
        background: #19233c;
        border: 1px solid #29b6f6;
        border-radius: 8px;
        padding: 14px;
        text-align: center;
    }

</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------------
# Database & Session Initialization
# -------------------------------------------------------------------
database.init_db()

if "session_id" not in st.session_state:
    st.session_state.session_id = f"sess_{uuid.uuid4().hex[:8]}"

if "task_scope" not in st.session_state:
    st.session_state.task_scope = TaskScope()

if "taint_tracker" not in st.session_state:
    st.session_state.taint_tracker = TaintTracker()

if "security_engine" not in st.session_state:
    st.session_state.security_engine = SecurityEngine(
        st.session_state.task_scope,
        st.session_state.taint_tracker
    )

if "interceptor" not in st.session_state:
    st.session_state.interceptor = Interceptor(
        st.session_state.security_engine,
        st.session_state.taint_tracker,
        st.session_state.session_id
    )

if "execution_result" not in st.session_state:
    st.session_state.execution_result = None

if "last_prompt" not in st.session_state:
    st.session_state.last_prompt = "No task run yet."

def reset_session():
    """Reset active security session state."""
    st.session_state.session_id = f"sess_{uuid.uuid4().hex[:8]}"
    st.session_state.task_scope = TaskScope()
    st.session_state.taint_tracker = TaintTracker()
    st.session_state.security_engine = SecurityEngine(
        st.session_state.task_scope,
        st.session_state.taint_tracker
    )
    st.session_state.interceptor = Interceptor(
        st.session_state.security_engine,
        st.session_state.taint_tracker,
        st.session_state.session_id
    )
    st.session_state.execution_result = None
    st.session_state.last_prompt = "No task run yet."

# -------------------------------------------------------------------
# Header & Sidebar Controls
# -------------------------------------------------------------------
col_hdr1, col_hdr2 = st.columns([8, 4])
with col_hdr1:
    st.title("🛡️ SentinelMesh")
    st.caption("AI Agent Security Guard — Real-Time Action Interceptor & Defense System")
with col_hdr2:
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("<span class='badge-safe' style='float:right;'>PROTOTYPE STATUS: 🟢 FUNCTIONAL MVP</span>", unsafe_allow_html=True)

with st.sidebar:
    st.header("⚡ Hackathon Demo Console")
    st.markdown("Run pre-configured scenarios or custom tasks to test the security proxy engine:")
    
    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        if st.button("▶ Run Safe Demo", use_container_width=True, type="primary"):
            reset_session()
            prompt = "Summarize normal_report.txt"
            st.session_state.last_prompt = prompt
            st.session_state.task_scope.set_scope_from_prompt(prompt)
            agent = MockAgent(st.session_state.interceptor)
            res = agent.run_task(prompt)
            st.session_state.execution_result = res
            st.rerun()

    with col_sb2:
        if st.button("⚠ Run Attack Demo", use_container_width=True):
            reset_session()
            prompt = "Summarize malicious_report.txt"
            st.session_state.last_prompt = prompt
            st.session_state.task_scope.set_scope_from_prompt(prompt)
            agent = MockAgent(st.session_state.interceptor)
            res = agent.run_task(prompt)
            st.session_state.execution_result = res
            st.rerun()

    st.divider()
    st.markdown("### 📖 Demo Guide")
    st.markdown("- **▶ Safe Demo**: Shows legitimate AI behavior within task scope.\n- **⚠ Attack Demo**: Shows prompt injection $\\rightarrow$ fake trap $\\rightarrow$ detection $\\rightarrow$ block.\n- **🚀 Custom Task**: Test a custom prompt or resource.")

    st.divider()
    st.markdown("### 💬 Run Custom Task Prompt")
    custom_prompt_input = st.text_input("Custom User Prompt", value="Summarize normal_report.txt", key="custom_prompt")
    if st.button("🚀 Execute Custom Task", use_container_width=True):
        st.session_state.last_prompt = custom_prompt_input
        st.session_state.task_scope.set_scope_from_prompt(custom_prompt_input)
        agent = MockAgent(st.session_state.interceptor)
        res = agent.run_task(custom_prompt_input)
        st.session_state.execution_result = res
        st.rerun()

    st.divider()
    
    if st.button("🔄 Reset Session", use_container_width=True):
        reset_session()
        st.success("Session state reset.")
        st.rerun()

    st.divider()
    st.markdown("### 🪤 Protected Decoy Resources")
    st.markdown("- `traps/fake_passwords.txt`\n- `traps/fake_api_keys.txt`\n- `traps/fake_company_secrets.txt` ")
    st.caption("**Task-Scoped Access**: Only resources required for the current task are permitted.")

    st.divider()
    st.caption("SQLite DB: `sentinelmesh.db`")
    if st.button("🗑️ Clear Demo Incident Log"):
        database.clear_events()
        st.toast("Database incident table cleared.")
        st.rerun()

# -------------------------------------------------------------------
# System Status Metric Cards (Requirement 1 & 2)
# -------------------------------------------------------------------
agent_locked = st.session_state.interceptor.is_agent_locked()
session_tainted = st.session_state.taint_tracker.is_tainted
timeline = st.session_state.interceptor.timeline

# Filter timeline to count actual tool/action events (exclude task_init)
action_events = [item for item in timeline if item.get("action") not in ["task_init", "init"]]
actions_monitored = len(action_events)

# Calculate threats detected and actions blocked
blocked_items = [item for item in action_events if str(item.get("status")).upper() in ["BLOCK", "BLOCKED"]]
actions_blocked = len(blocked_items)
threats_detected = 1 if (agent_locked or session_tainted or actions_blocked > 0) else 0

col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)

with col_stat1:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.markdown("<div class='metric-card-title'>1. SECURITY STATUS</div>", unsafe_allow_html=True)
    if agent_locked or actions_blocked > 0:
        st.markdown("<span class='badge-blocked'>🔴 THREAT BLOCKED</span>", unsafe_allow_html=True)
    elif session_tainted:
        st.markdown("<span class='badge-tainted'>⚠️ TAINTED</span>", unsafe_allow_html=True)
    else:
        st.markdown("<span class='badge-safe'>🟢 SAFE</span>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col_stat2:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.markdown("<div class='metric-card-title'>2. ACTIONS MONITORED</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='metric-card-value' style='color:#29b6f6;'>{actions_monitored}</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col_stat3:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.markdown("<div class='metric-card-title'>3. THREATS DETECTED</div>", unsafe_allow_html=True)
    color = "#ff1744" if threats_detected > 0 else "#00e676"
    st.markdown(f"<div class='metric-card-value' style='color:{color};'>{threats_detected}</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col_stat4:
    st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
    st.markdown("<div class='metric-card-title'>4. ACTIONS BLOCKED</div>", unsafe_allow_html=True)
    color = "#ff1744" if actions_blocked > 0 else "#00e676"
    st.markdown(f"<div class='metric-card-value' style='color:{color};'>{actions_blocked}</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# Active User Task & User Intent vs AI Action (Requirement 6)
# -------------------------------------------------------------------
if st.session_state.execution_result:
    res = st.session_state.execution_result
    status = res.get("status")

    st.markdown("### 🎯 User Intent vs AI Action")
    st.markdown("<div class='sec-card'>", unsafe_allow_html=True)

    if status in ["BLOCKED", "ATTACK_BLOCKED"] or agent_locked:
        col_i1, col_i2, col_i3 = st.columns(3)
        with col_i1:
            st.markdown("##### 👤 USER INTENT")
            st.info(f"**Prompt:** `{st.session_state.last_prompt}`")
        with col_i2:
            st.markdown("##### 🤖 AI ATTEMPTED ACTION")
            st.error("**Action:** `read_file('traps/fake_passwords.txt')`")
        with col_i3:
            st.markdown("##### 🛡️ SENTINELMESH ENFORCEMENT")
            st.markdown("<span class='badge-blocked'>🚫 BLOCKED</span>", unsafe_allow_html=True)
            st.markdown("<br><small style='color:#cbd5e1;'><strong>Reason:</strong> Requested resource is outside the permitted task scope and is a protected decoy resource.</small>", unsafe_allow_html=True)
    else:
        col_i1, col_i2, col_i3 = st.columns(3)
        with col_i1:
            st.markdown("##### 👤 USER INTENT")
            st.info(f"**Prompt:** `{st.session_state.last_prompt}`")
        with col_i2:
            st.markdown("##### 🤖 AI ACTION")
            st.success("**Action:** `read_file('test_data/normal_report.txt')`")
        with col_i3:
            st.markdown("##### 🛡️ SENTINELMESH ENFORCEMENT")
            st.markdown("<span class='badge-safe'>✓ ALLOWED</span>", unsafe_allow_html=True)
            st.markdown("<br><small style='color:#cbd5e1;'><strong>Reason:</strong> Action is within the permitted task scope.</small>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# Threat Alert & 'How SentinelMesh Stopped It' (Requirement 4 & 5)
# -------------------------------------------------------------------
if st.session_state.execution_result:
    res = st.session_state.execution_result
    status = res.get("status")
    final_risk = res.get("final_risk", {})
    
    if status in ["BLOCKED", "ATTACK_BLOCKED"] or agent_locked:
        st.markdown("""
        <div class='threat-banner'>
            <h2>🚨 THREAT DETECTED & INTERCEPTED</h2>
            <p style='color: #ffc400; font-size: 1.05rem; font-weight: 600; margin-bottom: 12px;'>
                An untrusted document attempted to manipulate the AI agent into accessing a sensitive resource outside the user's original task.
            </p>
            <div style='font-size: 1.15rem; font-weight: 800; margin-bottom: 14px; color: #ff1744;'>
                🚫 ACTION BLOCKED &nbsp;|&nbsp; 🔒 AGENT STATUS: LOCKED
            </div>
            <div style='text-align: left; max-width: 620px; margin: 0 auto; background: rgba(0,0,0,0.4); padding: 16px 24px; border-radius: 8px; border: 1px solid rgba(255,23,68,0.4);'>
                <strong style='color: #ff1744; font-size: 1rem;'>WHY WAS IT BLOCKED?</strong>
                <ul style='color: #e2e8f0; margin-top: 6px; margin-bottom: 12px; font-size: 0.95rem; line-height: 1.6;'>
                    <li>Outside the user's task scope (+35)</li>
                    <li>Sensitive decoy resource requested (+20)</li>
                    <li>Session was tainted by untrusted content (+15)</li>
                    <li>Fake data trap was triggered (+50 -> Mandatory Hard Block)</li>
                </ul>
                <div style='display: flex; justify-content: space-between; font-size: 1.1rem; font-weight: 800; color: #ff1744; border-top: 1px solid rgba(255,23,68,0.3); padding-top: 8px;'>
                    <span>Risk Score: 100 / 100</span>
                    <span>Decision: BLOCK</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Requirement 5: "How SentinelMesh Stopped the Attack" Step Box
        st.markdown("### 🛡️ How SentinelMesh Stopped the Attack")
        col_step1, col_step2, col_step3, col_step4 = st.columns(4)
        with col_step1:
            st.markdown("""
            <div class='step-box'>
                <div style='font-size: 1.5rem;'>🧠</div>
                <strong style='color: #29b6f6; font-size: 0.9rem;'>1. USER INTENT</strong>
                <p style='font-size: 0.8rem; color: #cbd5e1; margin-top: 4px; margin-bottom: 0;'>Summarize malicious_report.txt</p>
            </div>
            """, unsafe_allow_html=True)
        with col_step2:
            st.markdown("""
            <div class='step-box' style='border-color: #ffc400;'>
                <div style='font-size: 1.5rem;'>⚠️</div>
                <strong style='color: #ffc400; font-size: 0.9rem;'>2. TAINT DETECTION</strong>
                <p style='font-size: 0.8rem; color: #cbd5e1; margin-top: 4px; margin-bottom: 0;'>Untrusted injection detected</p>
            </div>
            """, unsafe_allow_html=True)
        with col_step3:
            st.markdown("""
            <div class='step-box' style='border-color: #ff1744;'>
                <div style='font-size: 1.5rem;'>🪤</div>
                <strong style='color: #ff1744; font-size: 0.9rem;'>3. FAKE TRAP</strong>
                <p style='font-size: 0.8rem; color: #cbd5e1; margin-top: 4px; margin-bottom: 0;'>fake_passwords.txt requested</p>
            </div>
            """, unsafe_allow_html=True)
        with col_step4:
            st.markdown("""
            <div class='step-box' style='border-color: #ff1744; background: rgba(255,23,68,0.15);'>
                <div style='font-size: 1.5rem;'>🛡️</div>
                <strong style='color: #ff1744; font-size: 0.9rem;'>4. ENFORCEMENT</strong>
                <p style='font-size: 0.8rem; color: #ff1744; font-weight: bold; margin-top: 4px; margin-bottom: 0;'>BLOCK + LOCK AGENT</p>
            </div>
            """, unsafe_allow_html=True)

    elif status == "SUCCESS":
        st.markdown("""
        <div class='safe-banner'>
            <h3 style='color:#00e676; margin:0;'>✅ TASK EXECUTED SAFELY</h3>
            <p style='margin: 5px 0 0 0;'>All tool calls were inside the permitted task scope. Zero threat detected.</p>
        </div>
        """, unsafe_allow_html=True)

# -------------------------------------------------------------------
# Main Content Columns: Live Timeline & Risk Breakdown (Requirement 7, 8, 9)
# -------------------------------------------------------------------
col_main1, col_main2 = st.columns([6, 6])

with col_main1:
    st.markdown("### ⏱️ Live Action Interceptor Timeline")
    st.caption("Real-time telemetry showing tool calls, risk evaluation, and inline security enforcement")

    timeline = st.session_state.interceptor.timeline
    if not timeline:
        st.info("No active tool calls logged in current session. Click 'Run Safe Demo' or 'Run Attack Demo' above.")
    else:
        for item in timeline:
            ts = item.get("timestamp")
            action = item.get("action")
            resource = item.get("resource")
            item_status = str(item.get("status")).upper()
            item_risk = item.get("risk_score", 0)
            details = item.get("details", [])

            if item_status in ["BLOCK", "BLOCKED"]:
                st.markdown(f"""
                <div class='timeline-node-blocked'>
                    <div style='display:flex; justify-content:space-between; align-items:center;'>
                        <strong style='color:#ff1744;'>🚫 {ts} — {action}('{resource}')</strong>
                        <span style='color:#ff1744; font-weight:bold;'>BLOCKED (Risk: {item_risk}/100)</span>
                    </div>
                    <div style='font-size:0.85rem; color:#cbd5e1; margin-top:4px;'>
                        {'<br>'.join(details)}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            elif item_status in ["TAINT_DETECTED", "TAINTED", "WARNING"]:
                st.markdown(f"""
                <div class='timeline-node-tainted'>
                    <div style='display:flex; justify-content:space-between; align-items:center;'>
                        <strong style='color:#ffc400;'>⚠️ {ts} — Document Analysis</strong>
                        <span style='color:#ffc400; font-weight:bold;'>SESSION TAINTED</span>
                    </div>
                    <div style='font-size:0.85rem; color:#cbd5e1; margin-top:4px;'>
                        {'<br>'.join(details)}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='timeline-node'>
                    <div style='display:flex; justify-content:space-between; align-items:center;'>
                        <strong style='color:#29b6f6;'>✓ {ts} — {action}('{resource}')</strong>
                        <span style='color:#00e676; font-weight:bold;'>ALLOWED (Risk: {item_risk}/100)</span>
                    </div>
                    <div style='font-size:0.85rem; color:#cbd5e1; margin-top:4px;'>
                        {'<br>'.join(details)}
                    </div>
                </div>
                """, unsafe_allow_html=True)

with col_main2:
    st.markdown("### 📊 Threat Signal Breakdown")
    st.caption("Transparent multi-signal risk matrix calculation")

    if st.session_state.execution_result and "final_risk" in st.session_state.execution_result:
        final_risk = st.session_state.execution_result["final_risk"]
        breakdown = final_risk.get("breakdown", {})
        reasons = final_risk.get("reasons", [])
        eval_score = final_risk.get('risk_score', 0)
        eval_decision = final_risk.get('decision', 'ALLOW')

        st.markdown("<div class='sec-card'>", unsafe_allow_html=True)
        st.markdown("#### Risk Signal Weights")
        
        signal_rows = [
            ("Outside Task Scope", 35, breakdown.get("Outside Task Scope", 0)),
            ("Sensitive Resource Access", 20, breakdown.get("Sensitive Resource", 0)),
            ("Fake Data Trap Touched", 50, breakdown.get("Fake Trap Touched", 0)),
            ("Tainted Session Context", 15, breakdown.get("Session Tainted", 0)),
            ("External Data Transfer Attempt", 25, breakdown.get("External Data Transfer", 0))
        ]

        for name, max_val, curr_val in signal_rows:
            col_s1, col_s2 = st.columns([8, 4])
            with col_s1:
                if curr_val > 0:
                    icon = "🚨" if name == "Fake Data Trap Touched" else "⚠️"
                    st.markdown(f"<span style='color:#ff1744; font-weight:600;'>{icon} {name}</span>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<span style='color:#64748b;'>✓ {name}</span>", unsafe_allow_html=True)
            with col_s2:
                if curr_val > 0:
                    st.markdown(f"<span style='color:#ff1744; font-weight:700;'>+{curr_val} pts</span>", unsafe_allow_html=True)
                else:
                    st.markdown("<span style='color:#64748b;'>+0 pts</span>", unsafe_allow_html=True)

        st.divider()

        # Requirement 8: Simple Horizontal Risk Meter
        risk_color = "#ff1744" if eval_decision == "BLOCK" else ("#ffc400" if eval_decision == "ASK USER" else "#00e676")
        st.markdown(f"**Calculated Risk Meter:**")
        st.markdown(f"""
        <div style="margin-top: 4px; margin-bottom: 12px;">
            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: #94a3b8; font-weight: 600;">
                <span>0 (SAFE)</span>
                <span>50 (ASK USER)</span>
                <span>100 (BLOCK)</span>
            </div>
            <div style="width: 100%; height: 10px; background: #1e2d4a; border-radius: 6px; overflow: hidden; margin-top: 4px;">
                <div style="width: {eval_score}%; height: 100%; background: {risk_color}; border-radius: 6px;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"**Total Calculated Risk:** <span style='font-size:1.25rem; font-weight:800; color:{risk_color};'>{eval_score} / 100</span>", unsafe_allow_html=True)
        st.markdown(f"**Final Security Decision:** <code style='font-weight:bold; color:{risk_color}; font-size:1.1rem;'>{eval_decision}</code>", unsafe_allow_html=True)

        if reasons:
            st.markdown("<br>**Evaluated Security Reasons:**", unsafe_allow_html=True)
            for r in reasons:
                st.markdown(f"- `{r}`")
                
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("Run a demo scenario from the sidebar to inspect the threat analysis breakdown.")

# -------------------------------------------------------------------
# Output Summary Section
# -------------------------------------------------------------------
if st.session_state.execution_result:
    st.markdown("### 📄 Agent Output / Summary Response")
    st.text_area(
        label="Agent Result Text",
        value=st.session_state.execution_result.get("summary", ""),
        height=120,
        disabled=True
    )

# -------------------------------------------------------------------
# SQLite Incident Log Table (Requirement 10 & 19)
# -------------------------------------------------------------------
st.divider()
st.markdown("### 🗄️ SQLite Security Incident Log (`events` table)")

events = database.get_events(limit=50, exclude_tests=True)
if events:
    df_events = pd.DataFrame(events)
    df_events["reasons_str"] = df_events["reasons"].apply(lambda r: ", ".join(r) if isinstance(r, list) else str(r))
    
    st.dataframe(
        df_events[["id", "timestamp", "session_id", "action", "resource", "risk_score", "decision", "reasons_str"]],
        use_container_width=True,
        hide_index=True
    )

    import json
    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        csv_data = df_events[["id", "timestamp", "session_id", "action", "resource", "risk_score", "decision", "reasons_str"]].to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Logs (CSV)",
            data=csv_data,
            file_name=f"sentinelmesh_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    with col_exp2:
        json_data = json.dumps(events, indent=2).encode('utf-8')
        st.download_button(
            label="📥 Export Logs (JSON)",
            data=json_data,
            file_name=f"sentinelmesh_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
else:
    st.info("No security incidents recorded in the database yet.")

# -------------------------------------------------------------------
# System Architecture Section (Requirement 12)
# -------------------------------------------------------------------
st.divider()
st.markdown("<div class='sec-card' style='text-align: center;'>", unsafe_allow_html=True)
st.markdown("<h4 style='color: #29b6f6; margin-bottom: 15px;'>🏗️ SentinelMesh Security Proxy Architecture</h4>", unsafe_allow_html=True)
st.markdown("""
<div style="display: flex; justify-content: center; align-items: center; gap: 10px; flex-wrap: wrap; font-weight: 600; font-size: 0.85rem;">
    <div style="background: #1e2d4a; padding: 10px 16px; border-radius: 8px; border: 1px solid #29b6f6;">👤 USER</div>
    <div style="color: #29b6f6;">➔</div>
    <div style="background: #1e2d4a; padding: 10px 16px; border-radius: 8px; border: 1px solid #29b6f6;">🤖 AI AGENT</div>
    <div style="color: #29b6f6;">➔</div>
    <div style="background: rgba(0, 230, 118, 0.15); padding: 12px 20px; border-radius: 8px; border: 1.5px solid #00e676; color: #00e676;">
        🛡️ SENTINELMESH INTERCEPTOR
        <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 4px;">Task Scope • Taint Tracker • Risk Engine • Policy</div>
    </div>
    <div style="color: #29b6f6;">➔</div>
    <div style="background: #1e2d4a; padding: 10px 16px; border-radius: 8px; border: 1px solid #ff1744; color: #ff1744;">ALLOW / BLOCK</div>
    <div style="color: #29b6f6;">➔</div>
    <div style="background: #1e2d4a; padding: 10px 16px; border-radius: 8px; border: 1px solid #29b6f6;">📁 TOOLS & RESOURCES</div>
</div>
""", unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)
