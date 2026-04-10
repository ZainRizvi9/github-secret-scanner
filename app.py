import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from scanner import scan_repo, scan_user
from datetime import datetime

st.set_page_config(
    page_title="SecretScan",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap');

*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

:root {
    --green: #00ff88;
    --green2: #00cc6a;
    --green3: #004422;
    --red: #ff4444;
    --orange: #ff8800;
    --yellow: #ffcc00;
    --bg: #080808;
    --bg2: #0e0e0e;
    --bg3: #141414;
    --border: #1a1a1a;
    --border2: #242424;
    --ink: #e0e0e0;
    --ink2: #888;
    --ink3: #444;
    --mono: 'JetBrains Mono', monospace;
}

html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg) !important;
    color: var(--ink) !important;
    font-family: var(--mono) !important;
}
[data-testid="stAppViewContainer"] { background: var(--bg) !important; }
[data-testid="stHeader"] { display: none !important; }
[data-testid="stSidebar"] { display: none !important; }
[data-testid="collapsedControl"] { display: none !important; }
section[data-testid="stSidebar"] { display: none !important; }
.stDeployButton { display: none !important; }
footer { display: none !important; }
#MainMenu { display: none !important; }
.block-container { padding: 0 !important; max-width: 100% !important; }

.scan-header {
    border-bottom: 1px solid var(--border2);
    padding: 1.5rem 3rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--bg);
}
.scan-logo { font-family: var(--mono); font-size: 0.8rem; color: var(--green); letter-spacing: 0.2em; text-transform: uppercase; }
.scan-logo span { color: var(--ink3); }
.scan-status { font-family: var(--mono); font-size: 0.7rem; color: var(--ink3); letter-spacing: 0.08em; }

.scan-hero {
    padding: 4rem 3rem 3rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.scan-hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at center top, rgba(0,255,136,0.04) 0%, transparent 70%);
    pointer-events: none;
}
.hero-tag { font-family: var(--mono); font-size: 0.65rem; color: var(--green); letter-spacing: 0.2em; text-transform: uppercase; margin-bottom: 1.5rem; opacity: 0.8; }
.hero-title { font-family: var(--mono); font-size: clamp(2.5rem, 5vw, 4.5rem); font-weight: 700; color: var(--ink); line-height: 1; margin-bottom: 0.5rem; letter-spacing: -0.02em; }
.hero-title .accent { color: var(--green); }
.hero-sub { font-family: var(--mono); font-size: 0.8rem; color: var(--ink2); margin-bottom: 3rem; letter-spacing: 0.04em; }

.scan-form-container { max-width: 720px; margin: 0 auto; padding: 0 2rem 3rem; }

.metrics-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    background: var(--border2);
    border: 1px solid var(--border2);
    margin: 0 3rem 2rem;
}
.metric-cell { background: var(--bg2); padding: 1.5rem 2rem; text-align: center; }
.metric-val { font-family: var(--mono); font-size: 2.5rem; font-weight: 700; line-height: 1; margin-bottom: 0.5rem; }
.metric-val.critical { color: var(--red); }
.metric-val.high { color: var(--orange); }
.metric-val.medium { color: var(--yellow); }
.metric-val.low { color: var(--green); }
.metric-val.zero { color: var(--ink3); }
.metric-label { font-family: var(--mono); font-size: 0.6rem; color: var(--ink3); letter-spacing: 0.14em; text-transform: uppercase; }

.terminal-block { margin: 0 3rem 2rem; border: 1px solid var(--border2); background: var(--bg2); overflow: hidden; }
.terminal-bar { background: var(--bg3); border-bottom: 1px solid var(--border2); padding: 0.6rem 1rem; display: flex; align-items: center; gap: 0.5rem; }
.terminal-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--border2); }
.terminal-title { font-family: var(--mono); font-size: 0.65rem; color: var(--ink3); letter-spacing: 0.08em; margin-left: 0.5rem; }
.terminal-content { padding: 1.5rem; font-family: var(--mono); font-size: 0.78rem; line-height: 2; color: var(--ink2); }
.t-line { display: flex; gap: 1rem; align-items: flex-start; }
.t-prompt { color: var(--green); flex-shrink: 0; }
.t-cmd { color: var(--ink); }
.t-comment { color: var(--ink3); }
.t-success { color: var(--green); }
.t-error { color: var(--red); }
.t-warn { color: var(--orange); }
.t-info { color: var(--yellow); }

.findings-container { margin: 0 3rem 2rem; }
.finding-row { border: 1px solid var(--border2); margin-bottom: 2px; background: var(--bg2); }
.finding-row:hover { border-color: var(--green3); }
.finding-header { padding: 1rem 1.5rem; display: grid; grid-template-columns: 80px 160px 1fr 120px auto; gap: 1rem; align-items: center; }
.sev-badge { font-family: var(--mono); font-size: 0.6rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; padding: 0.2rem 0.5rem; border-radius: 2px; text-align: center; }
.sev-critical { background: rgba(255,68,68,0.15); color: var(--red); border: 1px solid rgba(255,68,68,0.3); }
.sev-high { background: rgba(255,136,0,0.15); color: var(--orange); border: 1px solid rgba(255,136,0,0.3); }
.sev-medium { background: rgba(255,204,0,0.15); color: var(--yellow); border: 1px solid rgba(255,204,0,0.3); }
.sev-low { background: rgba(0,255,136,0.1); color: var(--green); border: 1px solid rgba(0,255,136,0.2); }
.detection-badge { font-family: var(--mono); font-size: 0.58rem; color: var(--ink3); border: 1px solid var(--border2); padding: 0.15rem 0.4rem; letter-spacing: 0.06em; }
.finding-type { font-family: var(--mono); font-size: 0.72rem; color: var(--ink); font-weight: 500; }
.finding-file { font-family: var(--mono); font-size: 0.68rem; color: var(--ink2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.finding-line { font-family: var(--mono); font-size: 0.65rem; color: var(--ink3); text-align: right; }
.finding-body { padding: 0 1.5rem 1.5rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; border-top: 1px solid var(--border); }
.finding-code-block { padding-top: 1rem; }
.finding-code-block label { font-family: var(--mono); font-size: 0.6rem; color: var(--ink3); letter-spacing: 0.1em; text-transform: uppercase; display: block; margin-bottom: 0.5rem; }
.finding-code-block code { font-family: var(--mono); font-size: 0.7rem; color: var(--red); word-break: break-all; line-height: 1.6; display: block; }
.finding-detail { padding-top: 1rem; }
.finding-detail label { font-family: var(--mono); font-size: 0.6rem; color: var(--ink3); letter-spacing: 0.1em; text-transform: uppercase; display: block; margin-bottom: 0.4rem; }
.finding-detail p { font-family: var(--mono); font-size: 0.7rem; color: var(--ink2); line-height: 1.7; }
.impact-box { background: rgba(255,68,68,0.05); border-left: 2px solid var(--red); padding: 0.75rem 1rem; margin-bottom: 1rem; }
.attack-box { background: rgba(255,136,0,0.05); border-left: 2px solid var(--orange); padding: 0.75rem 1rem; margin-bottom: 1rem; }
.fix-box { background: rgba(0,255,136,0.05); border-left: 2px solid var(--green); padding: 0.75rem 1rem; }

.section-header { margin: 0 3rem 1rem; display: flex; align-items: center; gap: 1rem; }
.section-title { font-family: var(--mono); font-size: 0.65rem; color: var(--green); letter-spacing: 0.14em; text-transform: uppercase; white-space: nowrap; }
.section-line { flex: 1; height: 1px; background: var(--border2); }

.repo-card { margin: 0 3rem 3rem; border: 1px solid var(--border2); background: var(--bg2); padding: 1.5rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1.5rem; }
.repo-field label { font-family: var(--mono); font-size: 0.6rem; color: var(--ink3); letter-spacing: 0.1em; text-transform: uppercase; display: block; margin-bottom: 0.3rem; }
.repo-field span { font-family: var(--mono); font-size: 0.8rem; color: var(--ink); }

div[data-testid="stSelectbox"] > div,
div[data-testid="stTextInput"] > div > div > input,
div[data-testid="stMultiSelect"] > div {
    background: var(--bg2) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 0 !important;
    color: var(--ink) !important;
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
}
div[data-testid="stTextInput"] > div > div > input { padding: 0.75rem 1rem !important; }
div[data-testid="stTextInput"] > div > div > input:focus { border-color: var(--green) !important; box-shadow: 0 0 0 1px var(--green3) !important; }
div[data-testid="stTextInput"] label,
div[data-testid="stSelectbox"] label,
div[data-testid="stMultiSelect"] label {
    font-family: var(--mono) !important;
    font-size: 0.65rem !important;
    color: var(--ink3) !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
}
div[data-testid="stButton"] button {
    background: var(--green) !important;
    color: #000 !important;
    border: none !important;
    border-radius: 0 !important;
    font-family: var(--mono) !important;
    font-size: 0.75rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    padding: 0.75rem 2rem !important;
    width: 100% !important;
}
div[data-testid="stButton"] button:hover { background: var(--green2) !important; }
div[data-testid="stDownloadButton"] button {
    background: transparent !important;
    color: var(--green) !important;
    border: 1px solid var(--green3) !important;
    border-radius: 0 !important;
    font-family: var(--mono) !important;
    font-size: 0.7rem !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
}
div[data-testid="stAlert"] { border-radius: 0 !important; font-family: var(--mono) !important; font-size: 0.78rem !important; }
div[data-testid="stPlotlyChart"] { border: 1px solid var(--border2) !important; }
[data-testid="stMarkdownContainer"] p { font-family: var(--mono) !important; font-size: 0.8rem !important; color: var(--ink2) !important; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="scan-header">
    <div class="scan-logo">Secret<span>//</span>Scan</div>
    <div class="scan-status">v2.0 &nbsp;|&nbsp; pattern + entropy detection &nbsp;|&nbsp; public repos only</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="scan-hero">
    <div class="hero-tag">// security research tool</div>
    <div class="hero-title">Find Exposed <span class="accent">Secrets</span></div>
    <div class="hero-sub">Scans public GitHub repos for credentials using pattern matching and Shannon entropy detection</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="scan-form-container">', unsafe_allow_html=True)

col1, col2 = st.columns([3, 1])
with col1:
    scan_type = st.selectbox("Scan Mode", ["Single Repository", "User Repositories"])
with col2:
    if scan_type == "User Repositories":
        max_repos = st.selectbox("Max Repos", [3, 5, 10, 20], index=1)
    else:
        st.markdown("<div style='height:68px'></div>", unsafe_allow_html=True)

if scan_type == "Single Repository":
    target = st.text_input("Repository", placeholder="username/repository-name")
else:
    target = st.text_input("GitHub Username", placeholder="username")

token = st.text_input("GitHub Personal Access Token", type="password", placeholder="ghp_xxxxxxxxxxxxxxxxxxxx")
severity_filter = st.multiselect("Severity Filter", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
scan_clicked = st.button("Run Scan", type="primary")
st.markdown('</div>', unsafe_allow_html=True)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEV_CLASS = {"Critical": "sev-critical", "High": "sev-high", "Medium": "sev-medium", "Low": "sev-low"}
SEV_METRIC = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}

st.markdown("<div style='margin-top: 2rem'></div>", unsafe_allow_html=True)

if scan_clicked:
    if not token:
        st.error("GitHub token required.")
    elif not target:
        st.error("Target required.")
    else:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        st.markdown(f"""
        <div class="terminal-block">
            <div class="terminal-bar">
                <div class="terminal-dot"></div><div class="terminal-dot"></div><div class="terminal-dot"></div>
                <span class="terminal-title">secretscan — bash</span>
            </div>
            <div class="terminal-content">
                <div class="t-line"><span class="t-prompt">$</span><span class="t-cmd">secretscan --target {target} --mode {"repo" if scan_type == "Single Repository" else "user"} --entropy on</span></div>
                <div class="t-line"><span class="t-prompt"> </span><span class="t-comment"># Initializing at {scan_time}</span></div>
                <div class="t-line"><span class="t-prompt"> </span><span class="t-comment"># Running pattern matching across 14 secret types...</span></div>
                <div class="t-line"><span class="t-prompt"> </span><span class="t-comment"># Running Shannon entropy analysis (threshold: 4.5 bits/char)...</span></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        with st.spinner("Scanning..."):
            if scan_type == "Single Repository":
                findings, repo_info = scan_repo(token, target)
                repos_info = [repo_info]
            else:
                findings, repos_info = scan_user(token, target, max_repos)

        if repos_info and "error" in repos_info[0]:
            st.error(f"Scan failed: {repos_info[0]['error']}")
        else:
            filtered = [f for f in findings if f["severity"] in severity_filter]
            filtered.sort(key=lambda x: SEVERITY_ORDER[x["severity"]])

            critical = len([f for f in filtered if f["severity"] == "Critical"])
            high = len([f for f in filtered if f["severity"] == "High"])
            medium = len([f for f in filtered if f["severity"] == "Medium"])
            low = len([f for f in filtered if f["severity"] == "Low"])
            total = len(filtered)
            files_scanned = sum(r.get("files_scanned", 0) for r in repos_info if "error" not in r)
            pattern_count = len([f for f in filtered if f.get("detection_method") == "pattern"])
            entropy_count = len([f for f in filtered if f.get("detection_method") == "entropy"])

            st.markdown(f"""
            <div class="terminal-block">
                <div class="terminal-bar">
                    <div class="terminal-dot"></div><div class="terminal-dot"></div><div class="terminal-dot"></div>
                    <span class="terminal-title">scan complete</span>
                </div>
                <div class="terminal-content">
                    <div class="t-line"><span class="t-prompt"> </span><span class="t-success">✓ Scan complete — {files_scanned} files across {len(repos_info)} repo(s)</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="t-comment">  Pattern findings:  {pattern_count}</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="t-comment">  Entropy findings:  {entropy_count}</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="t-comment">  ───────────────────────────────</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="{'t-error' if critical > 0 else 't-comment'}">  CRITICAL   {critical}</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="{'t-warn' if high > 0 else 't-comment'}">  HIGH       {high}</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="{'t-info' if medium > 0 else 't-comment'}">  MEDIUM     {medium}</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="{'t-success' if low > 0 else 't-comment'}">  LOW        {low}</span></div>
                    <div class="t-line"><span class="t-prompt"> </span><span class="t-cmd">  TOTAL      {total}</span></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown(f"""
            <div class="metrics-row">
                <div class="metric-cell">
                    <div class="metric-val {'critical' if critical > 0 else 'zero'}">{critical}</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="metric-cell">
                    <div class="metric-val {'high' if high > 0 else 'zero'}">{high}</div>
                    <div class="metric-label">High</div>
                </div>
                <div class="metric-cell">
                    <div class="metric-val {'medium' if medium > 0 else 'zero'}">{medium}</div>
                    <div class="metric-label">Medium</div>
                </div>
                <div class="metric-cell">
                    <div class="metric-val {'low' if low > 0 else 'zero'}">{low}</div>
                    <div class="metric-label">Low</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            if filtered:
                col1, col2 = st.columns(2)
                with col1:
                    fig1 = go.Figure(go.Bar(
                        x=["Critical", "High", "Medium", "Low"],
                        y=[critical, high, medium, low],
                        marker_color=["#ff4444", "#ff8800", "#ffcc00", "#00ff88"],
                        marker_line_width=0,
                    ))
                    fig1.update_layout(
                        title=dict(text="Findings by Severity", font=dict(family="JetBrains Mono", size=11, color="#888"), x=0),
                        plot_bgcolor="#0e0e0e", paper_bgcolor="#0e0e0e",
                        font=dict(family="JetBrains Mono", color="#888", size=10),
                        xaxis=dict(gridcolor="#1a1a1a", linecolor="#242424"),
                        yaxis=dict(gridcolor="#1a1a1a", linecolor="#242424"),
                        margin=dict(l=20, r=20, t=40, b=20), height=260,
                    )
                    st.plotly_chart(fig1, use_container_width=True)

                with col2:
                    method_counts = {"Pattern Match": pattern_count, "Entropy Detection": entropy_count}
                    fig2 = go.Figure(go.Pie(
                        labels=list(method_counts.keys()),
                        values=list(method_counts.values()),
                        hole=0.6,
                        marker=dict(colors=["#00ff88", "#ffcc00"]),
                        textfont=dict(family="JetBrains Mono", size=10),
                    ))
                    fig2.update_layout(
                        title=dict(text="Detection Method", font=dict(family="JetBrains Mono", size=11, color="#888"), x=0),
                        plot_bgcolor="#0e0e0e", paper_bgcolor="#0e0e0e",
                        font=dict(family="JetBrains Mono", color="#888", size=10),
                        margin=dict(l=20, r=20, t=40, b=20), height=260,
                        legend=dict(font=dict(size=9, family="JetBrains Mono"), bgcolor="rgba(0,0,0,0)")
                    )
                    st.plotly_chart(fig2, use_container_width=True)

                st.markdown("""
                <div class="section-header">
                    <span class="section-title">Findings</span>
                    <div class="section-line"></div>
                </div>
                """, unsafe_allow_html=True)

                findings_html = '<div class="findings-container">'
                for f in filtered:
                    file_url = f.get("file_url", "#")
                    detection = f.get("detection_method", "pattern")
                    entropy_score = f.get("entropy_score")
                    entropy_display = f" &nbsp; entropy: {entropy_score}" if entropy_score else ""
                    gh_link = f"<a href='{file_url}' style='font-family:JetBrains Mono;font-size:0.65rem;color:#00ff88;margin-top:0.75rem;display:inline-block;' target='_blank'>View on GitHub &rarr;</a>" if file_url != "#" else ""

                    impact = f.get("impact", "")
                    attack = f.get("attack", "")
                    remediation = f.get("remediation", "")

                    findings_html += f"""
                    <div class="finding-row">
                        <div class="finding-header">
                            <span class="sev-badge {SEV_CLASS[f['severity']]}">{f['severity']}</span>
                            <span class="finding-type">{f['secret_type']}</span>
                            <span class="finding-file">{f['filename']}</span>
                            <span class="detection-badge">{detection}{entropy_display}</span>
                            <span class="finding-line">L{f['line_number']}</span>
                        </div>
                        <div class="finding-body">
                            <div>
                                <div class="finding-code-block">
                                    <label>Exposed Line</label>
                                    <code>{f['line_preview'][:150]}</code>
                                    {gh_link}
                                </div>
                            </div>
                            <div>
                                <div class="impact-box">
                                    <label style="font-family:JetBrains Mono;font-size:0.6rem;color:#ff4444;letter-spacing:0.1em;text-transform:uppercase;display:block;margin-bottom:0.4rem;">Impact</label>
                                    <p style="font-family:JetBrains Mono;font-size:0.7rem;color:#888;line-height:1.7;">{impact}</p>
                                </div>
                                <div class="attack-box">
                                    <label style="font-family:JetBrains Mono;font-size:0.6rem;color:#ff8800;letter-spacing:0.1em;text-transform:uppercase;display:block;margin-bottom:0.4rem;">Attack Vector</label>
                                    <p style="font-family:JetBrains Mono;font-size:0.7rem;color:#888;line-height:1.7;">{attack}</p>
                                </div>
                                <div class="fix-box">
                                    <label style="font-family:JetBrains Mono;font-size:0.6rem;color:#00ff88;letter-spacing:0.1em;text-transform:uppercase;display:block;margin-bottom:0.4rem;">Remediation</label>
                                    <p style="font-family:JetBrains Mono;font-size:0.7rem;color:#888;line-height:1.7;">{remediation}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    """
                findings_html += '</div>'
                st.markdown(findings_html, unsafe_allow_html=True)

                st.markdown("<div style='margin: 1rem 3rem 0;'>", unsafe_allow_html=True)
                df = pd.DataFrame(filtered)
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Export CSV Report",
                    data=csv,
                    file_name=f"secretscan_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
                st.markdown("</div>", unsafe_allow_html=True)

            else:
                st.markdown("""
                <div class="terminal-block" style="margin: 0 3rem;">
                    <div class="terminal-content">
                        <div class="t-line"><span class="t-prompt"> </span><span class="t-success">✓ No secrets found. Repository appears clean.</span></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("""
            <div class="section-header" style="margin-top: 2rem;">
                <span class="section-title">Scanned Repositories</span>
                <div class="section-line"></div>
            </div>
            """, unsafe_allow_html=True)

            repo_html = '<div class="repo-card">'
            for repo in repos_info:
                if "error" not in repo:
                    repo_html += f"""
                    <div class="repo-field"><label>Repository</label><span>{repo.get('name', 'N/A')}</span></div>
                    <div class="repo-field"><label>Language</label><span>{repo.get('language', 'N/A')}</span></div>
                    <div class="repo-field"><label>Stars</label><span>{repo.get('stars', 0)}</span></div>
                    <div class="repo-field"><label>Files Scanned</label><span>{repo.get('files_scanned', 0)}</span></div>
                    <div class="repo-field"><label>Scanned At</label><span>{repo.get('scanned_at', 'N/A')}</span></div>
                    """
            repo_html += '</div>'
            st.markdown(repo_html, unsafe_allow_html=True)

else:
    st.markdown("""
    <div class="terminal-block" style="margin: 0 3rem;">
        <div class="terminal-bar">
            <div class="terminal-dot"></div><div class="terminal-dot"></div><div class="terminal-dot"></div>
            <span class="terminal-title">secretscan — ready</span>
        </div>
        <div class="terminal-content">
            <div class="t-line"><span class="t-prompt">$</span><span class="t-cmd">secretscan --help</span></div>
            <div class="t-line"><span class="t-prompt"> </span><span class="t-comment"># Enter a GitHub repo or username above and hit Run Scan</span></div>
            <div class="t-line"><span class="t-prompt"> </span><span class="t-comment"># Pattern matching: 14 secret types (AWS, Stripe, JWT, DB URLs...)</span></div>
            <div class="t-line"><span class="t-prompt"> </span><span class="t-comment"># Entropy analysis: flags high-randomness strings (threshold: 4.5 bits)</span></div>
            <div class="t-line"><span class="t-prompt"> </span><span class="t-comment"># Each finding includes impact, attack vector, and remediation steps</span></div>
            <div class="t-line"><span class="t-prompt"> </span><span class="t-success">▋</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("""
<div style="border-top: 1px solid #1a1a1a; padding: 1.5rem 3rem; margin-top: 4rem; display: flex; justify-content: space-between; align-items: center;">
    <span style="font-family: JetBrains Mono; font-size: 0.65rem; color: #444; letter-spacing: 0.08em;">SecretScan — Educational and security research use only</span>
    <span style="font-family: JetBrains Mono; font-size: 0.65rem; color: #444; letter-spacing: 0.08em;">github.com/ZainRizvi9</span>
</div>
""", unsafe_allow_html=True)