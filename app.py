"""
BEC Detection Platform — Streamlit UI
Run: streamlit run app.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time as time_module  # not named `time`: `from datetime import time` would shadow and break .sleep()
from datetime import date, datetime
from datetime import time as dt_time
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from bec_app.database import (
    add_user,
    fetch_alerts,
    fetch_analyses,
    fetch_audit,
    fetch_users,
    get_setting,
    init_db,
    insert_alert,
    insert_analysis,
    log_audit,
    row_to_dict,
    set_setting,
    update_alert_status,
)
from bec_app.features import (
    api_payload_to_features,
    csv_row_to_features,
    manual_to_features,
    suggest_column_map,
)
from bec_app.ml_engine import dashboard_series, detect_issues, score_fused, threat_level
from bec_app.model_service import clear_behavior_cache
from bec_app.phishing_model import clear_phishing_cache, get_phishing_pipeline
from bec_app.ui.styles import inject_global_css, pipeline_html

REPO_ROOT = Path(__file__).resolve().parent


def nav_to(name: str) -> None:
    st.session_state.page = name
    st.rerun()


def sidebar():
    with st.sidebar:
        st.markdown("### 🛡️ **BEC Shield**")
        st.caption("End-to-end BEC detection — input → AI → alerts → dashboard")
        st.divider()
        for label, key in [
            ("🏠 Landing", "landing"),
            ("📥 Input hub", "input"),
            ("📚 Datasets / benchmarks", "benchmarks"),
            ("⚙️ Processing", "processing"),
            ("📊 Results", "results"),
            ("🔔 Alerts", "alerts"),
            ("📈 Dashboard", "dashboard"),
            ("🔧 Admin", "admin"),
        ]:
            if st.button(label, key=f"nav_{key}", use_container_width=True):
                nav_to(key)
        st.divider()
        st.caption("IF · Phishing LR · Enron/CERT/sim benchmarks")


def run_analysis(
    input_type: str,
    features: dict,
    raw_summary: str | None = None,
    email_subject: str | None = None,
    email_body: str | None = None,
) -> dict:
    threshold = float(get_setting("risk_threshold", "0.55"))
    combined, behavior_risk, phish_p, raw_ml, beh_src = score_fused(
        features,
        subject=email_subject,
        body=email_body,
    )
    level = threat_level(combined, threshold)
    issues = detect_issues(features, combined, phish_p)
    aid = insert_analysis(input_type, combined, level, issues, features, raw_summary)
    if level == "High":
        insert_alert(
            "High",
            "High BEC risk detected",
            f"Combined {combined:.2f} (behavior {behavior_risk:.2f}) · {aid[:8]}…",
            aid,
        )
    elif level == "Medium":
        insert_alert(
            "Medium",
            "Elevated BEC risk",
            f"Combined {combined:.2f} (behavior {behavior_risk:.2f}) · {aid[:8]}…",
            aid,
        )
    log_audit("analysis", f"{input_type} {aid[:8]} combined={combined:.2f}")
    return {
        "analysis_id": aid,
        "risk": combined,
        "behavior_risk": behavior_risk,
        "phishing_prob": phish_p,
        "behavior_source": beh_src,
        "raw_ml": raw_ml,
        "level": level,
        "issues": issues,
        "features": features,
    }


def page_landing():
    st.markdown(
        f'<div class="hero-wrap"><div class="hero-title">BEC Detection Platform</div>'
        f'<p class="tagline">Detect BEC attacks in real time using AI — from ingest to alert.</p></div>',
        unsafe_allow_html=True,
    )
    c1, c2, c3 = st.columns([1, 1, 1])
    with c1:
        if st.button("📂 Upload & analyze", type="primary", use_container_width=True):
            nav_to("input")
    with c2:
        if st.button("🔗 Connect email (demo)", use_container_width=True):
            nav_to("input")
    with c3:
        if st.button("📈 Open dashboard", use_container_width=True):
            nav_to("dashboard")
    st.markdown("---")
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        st.markdown(
            "**🤖 AI detection**  \nIF on auth/behavior + TF‑IDF/LR (Enron + phishing corpora)"
        )
    with fc2:
        st.markdown("**⚡ Real-time alerts**  \nSeverity + triage actions")
    with fc3:
        st.markdown("**📊 Risk dashboard**  \nTrends, geography, volume")
    st.info(
        "**Killer line for judges:** We did not just train a model — we shipped a complete security product: "
        "multi-source ingest, ML scoring, alerting, and an operator dashboard."
    )


def page_input():
    st.header("Input hub")
    st.caption("CSV upload · API-style JSON · Manual narrative fields — flexibility wins hackathons.")
    tab_csv, tab_api, tab_manual = st.tabs(["📂 Upload CSV", "🔗 API / Email (demo)", "✍️ Manual input"])

    features_out = None
    meta_type = "manual"
    raw_summary = None

    with tab_csv:
        f = st.file_uploader("Email / login logs (CSV)", type=["csv"])
        if f:
            try:
                df = pd.read_csv(f, encoding="utf-8")
            except UnicodeDecodeError:
                f.seek(0)
                df = pd.read_csv(f, encoding="latin-1")
            except pd.errors.EmptyDataError:
                st.error("CSV file is empty or has no parseable rows.")
                df = None
            except pd.errors.ParserError as e:
                st.error(f"CSV parse error: {e}")
                df = None
            except Exception as e:
                st.error(f"Could not read CSV: {e}")
                df = None
            if df is not None and df.empty:
                st.error("CSV has no data rows.")
            elif df is not None:
                st.dataframe(df.head(12), use_container_width=True)
                cmap = suggest_column_map(list(df.columns))
                st.caption("Auto-mapped columns (edit if needed):")
                edited = {}
                cols = st.columns(2)
                keys = list(
                    {
                        "login_time_delta_hours",
                        "location_distance_km",
                        "emails_per_hour",
                        "recipient_count",
                        "inbox_rule_changes",
                        "subject",
                        "body",
                    }
                )
                for i, k in enumerate(keys):
                    opts = [""] + list(df.columns)
                    idx = opts.index(cmap[k]) if k in cmap and cmap[k] in opts else 0
                    with cols[i % 2]:
                        edited[k] = st.selectbox(k, opts, index=idx, key=f"map_{k}")
                cmap2 = {k: edited[k] for k in edited if edited[k]}
                max_idx = len(df) - 1
                row_idx = st.number_input(
                    "Row to analyze (0 = first data row)",
                    min_value=0,
                    max_value=max(0, max_idx),
                    value=0,
                    step=1,
                    key="csv_row_idx",
                )
                if st.button("Queue CSV row for analysis", key="csv_go"):
                    row = df.iloc[int(row_idx)]
                    features_out = csv_row_to_features(row, cmap2)
                    meta_type = "csv"
                    raw_summary = f"CSV rows={len(df)}, row_index={row_idx}"
                    subj_txt, body_txt = "", ""
                    if "subject" in cmap2:
                        v = row[cmap2["subject"]]
                        subj_txt = "" if pd.isna(v) else str(v)
                    if "body" in cmap2:
                        v = row[cmap2["body"]]
                        body_txt = "" if pd.isna(v) else str(v)
                    st.session_state.pending = (
                        meta_type,
                        features_out,
                        raw_summary,
                        subj_txt,
                        body_txt,
                    )
                    st.success(f"Row {row_idx} queued — open **Processing**.")

    with tab_api:
        st.markdown("Simulate **Gmail / Outlook** webhook or SIEM payload:")
        default_j = """{
  "login_time_delta_hours": 6,
  "location_distance_km": 4200,
  "emails_per_hour": 55,
  "recipient_count": 12,
  "inbox_rule_changes": 2,
  "subject_entropy": 5.1,
  "body_length_ratio": 3.2
}"""
        jtxt = st.text_area("JSON body", value=default_j, height=220)
        if st.button("Parse & queue analysis", key="api_go"):
            try:
                payload = json.loads(jtxt)
                if not isinstance(payload, dict):
                    st.error("JSON must be an object with numeric fields, not an array or primitive.")
                else:
                    features_out = api_payload_to_features(payload)
                    meta_type = "api"
                    raw_summary = jtxt[:500]
                    subj = str(
                        payload.get("subject")
                        or payload.get("email_subject")
                        or ""
                    )
                    bod = str(
                        payload.get("body")
                        or payload.get("content")
                        or payload.get("email_body")
                        or ""
                    )
                    st.session_state.pending = (
                        meta_type,
                        features_out,
                        raw_summary,
                        subj,
                        bod,
                    )
                    st.success("Payload queued — go to **Processing** to run the pipeline.")
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")

    with tab_manual:
        c1, c2 = st.columns(2)
        with c1:
            sender = st.text_input("Sender", "ceo@acme-corp.com")
            receiver = st.text_input("Receiver", "finance@acme-corp.com")
            subject = st.text_input("Subject", "Urgent: Wire transfer")
            body = st.text_area("Email body", "Please process the attached payment today.", height=100)
        with c2:
            login_lat = st.number_input("Login latitude", value=37.77, format="%.4f")
            login_lon = st.number_input("Login longitude", value=-122.42, format="%.4f")
            base_lat = st.number_input("Baseline latitude", value=40.71, format="%.4f")
            base_lon = st.number_input("Baseline longitude", value=-74.01, format="%.4f")
            recipients = st.number_input("Recipient count", min_value=0, value=3)
            rules = st.number_input("Inbox rule changes (window)", min_value=0, value=1)
        cdt1, cdt2 = st.columns(2)
        with cdt1:
            ld = st.date_input("Login date", value=date.today())
            lt = st.time_input("Login time", value=datetime.now().time())
        with cdt2:
            use_prev = st.checkbox("Provide previous login (for travel delta)", value=True)
            if use_prev:
                pd_ = st.date_input("Previous login date", value=date.today())
                pt_ = st.time_input("Previous login time", value=dt_time(8, 0))
            else:
                pd_, pt_ = None, None
        if st.button("Build features & queue", key="man_go"):
            t1 = datetime.combine(ld, lt)
            t2 = datetime.combine(pd_, pt_) if use_prev and pd_ else None
            features_out = manual_to_features(
                sender,
                receiver,
                subject,
                body,
                float(login_lat),
                float(login_lon),
                float(base_lat),
                float(base_lon),
                t1,
                t2,
                int(recipients),
                int(rules),
            )
            meta_type = "manual"
            raw_summary = f"{sender} → {receiver}: {subject}"
            st.session_state.pending = (
                meta_type,
                features_out,
                raw_summary,
                subject,
                body,
            )
            st.success("Queued — open **Processing** to run ML + rules.")

    if st.session_state.get("pending"):
        st.info("You have a queued analysis. Switch to **Processing** in the sidebar.")


def page_benchmarks():
    st.header("Datasets & benchmarks")
    st.markdown(
        "Hackathon stack: **Enron** (normal mail), **phishing** (labeled), "
        "**CERT insider threat** (logon behavior), **simulated M365/Gmail** logs. "
        "Place full Kaggle/CERT exports under `data/external/` and read `data/benchmarks/README.md`."
    )
    bcol1, bcol2 = st.columns(2)
    with bcol1:
        st.subheader("Model status")
        pipe = get_phishing_pipeline()
        st.write(
            "- **Phishing / BEC text head (TF‑IDF + LR):** "
            + ("✅ loaded" if pipe is not None else "⚪ not trained — run CLI below")
        )
        try:
            from bec_app.model_service import get_model_bundle

            _s, _c, src = get_model_bundle()
            st.write(f"- **Behavior Isolation Forest:** source = **{src}**")
        except Exception as e:
            st.write(f"- **Behavior IF:** error {e}")
    with bcol2:
        st.subheader("Reload caches")
        if st.button("Clear model caches (after training)"):
            clear_behavior_cache()
            clear_phishing_cache()
            st.success("Done. Next analysis loads fresh `data/artifacts/*.joblib` files.")

    st.subheader("Train on your downloads")
    st.code(
        "python scripts/train_benchmark_models.py\n"
        "# With Kaggle / CERT files:\n"
        "python scripts/train_benchmark_models.py "
        "--enron data/external/enron.csv --phishing data/external/phish.csv "
        "--cert-logon data/external/logon.csv --sim-auth data/generated/sim_m365_gmail_auth.csv",
        language="bash",
    )
    if st.button("Run training now (toy Enron+phish + synthetic IF)"):
        with st.spinner("Training…"):
            r = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "train_benchmark_models.py")],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=300,
            )
        st.text(r.stdout + (r.stderr or ""))
        if r.returncode == 0:
            clear_behavior_cache()
            clear_phishing_cache()
            st.success("Artifacts written to data/artifacts/. Caches cleared.")
        else:
            st.error(f"Exit code {r.returncode}")

    st.subheader("Simulated Microsoft 365 / Gmail auth logs")
    st.caption("Generates structured CSV aligned with the same 7 features as the app.")
    if st.button("Generate CSV (300 rows, default path)"):
        r = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "generate_auth_logs.py")],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        st.text(r.stdout + (r.stderr or ""))
        p = REPO_ROOT / "data" / "generated" / "sim_m365_gmail_auth.csv"
        if p.exists():
            st.download_button(
                label="Download sim_m365_gmail_auth.csv",
                data=p.read_bytes(),
                file_name="sim_m365_gmail_auth.csv",
                mime="text/csv",
            )


def _normalize_pending(p):
    if p is None:
        return None
    if len(p) == 5:
        return p
    if len(p) == 3:
        return (*p, "", "")
    return (*p[:3], "", "")


def page_processing():
    st.header("Processing pipeline")
    st.markdown(pipeline_html(), unsafe_allow_html=True)
    pending = _normalize_pending(st.session_state.get("pending"))
    if not pending:
        st.warning("No data queued. Use **Input hub** first.")
        return
    meta_type, feats, raw, em_sub, em_body = pending
    if st.button("▶ Run pipeline", type="primary"):
        status = st.empty()
        prog = st.progress(0)
        status.caption("Data input")
        time_module.sleep(0.35)
        prog.progress(20)
        status.caption("Preprocessing")
        time_module.sleep(0.35)
        prog.progress(45)
        status.caption("Rule engine")
        time_module.sleep(0.35)
        prog.progress(70)
        status.caption("ML — Isolation Forest")
        time_module.sleep(0.45)
        prog.progress(90)
        status.caption("Risk scoring")
        res = run_analysis(
            meta_type,
            feats,
            raw,
            email_subject=em_sub or None,
            email_body=em_body or None,
        )
        prog.progress(100)
        status.caption("Done")
        st.session_state.last_result = res
        st.session_state.pop("pending", None)
        time_module.sleep(0.2)
        nav_to("results")
    with st.expander("Feature vector (debug)"):
        st.json(feats)


def page_results():
    st.header("Results")
    r = st.session_state.last_result
    if not r:
        st.info("Run an analysis from **Input** → **Processing**.")
        return
    risk_pct = r["risk"] * 100
    br = r.get("behavior_risk")
    pp = r.get("phishing_prob")
    bsrc = r.get("behavior_source", "")
    if br is not None and pp is not None:
        st.caption(
            f"**Fused score** — behavior IF ({bsrc}): {br * 100:.1f} · "
            f"phishing LR: {pp * 100:.1f} → combined {risk_pct:.1f}"
        )
    elif br is not None:
        msg = f"Behavior IF ({bsrc}): {br * 100:.1f}."
        if pp is None:
            msg += " Train phishing head under **Datasets / benchmarks** for text fusion."
        st.caption(msg)
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        color = "#22c55e" if r["level"] == "Low" else "#eab308" if r["level"] == "Medium" else "#ef4444"
        st.markdown(
            f'<div class="metric-card"><div style="color:#94a3b8;font-size:0.85rem;">Risk score</div>'
            f'<div class="risk-ring" style="color:{color};">{risk_pct:.1f}</div>'
            f'<div style="color:#64748b;">/ 100</div></div>',
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f'<div class="metric-card"><div style="color:#94a3b8;">Threat level</div>'
            f'<div style="font-size:1.75rem;font-weight:700;margin-top:0.5rem;">{r["level"]}</div>'
            f'<div style="color:#64748b;font-size:0.85rem;">Analysis <code>{r["analysis_id"][:8]}…</code></div></div>',
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown("**Detected issues**")
        for issue in r.get("issues") or []:
            sev = issue.get("severity", "Low")
            icon = "🔴" if sev == "High" else "🟡" if sev == "Medium" else "🟢"
            itype = issue.get("type", "Issue")
            st.markdown(f"- {icon} **{itype}** — {issue.get('detail', '')}")
    st.plotly_chart(
        go.Figure(
            data=go.Indicator(
                mode="gauge+number",
                value=min(100, risk_pct),
                title={"text": "Composite risk"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": color},
                    "steps": [
                        {"range": [0, 40], "color": "rgba(34,197,94,0.25)"},
                        {"range": [40, 70], "color": "rgba(234,179,8,0.25)"},
                        {"range": [70, 100], "color": "rgba(239,68,68,0.3)"},
                    ],
                },
            )
        ).update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#e8eef4")),
        use_container_width=True,
    )


def page_alerts():
    st.header("Real-time alerts")
    rows = fetch_alerts(120)
    if not rows:
        st.caption("No alerts yet — run analyses with elevated risk.")
        return
    for row in rows:
        sev = row["severity"]
        badge = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")
        with st.container():
            b1, b2 = st.columns([4, 2])
            with b1:
                st.markdown(f"**{badge} {sev}** · {row['title']}  \n_{row['created_at']}_  \n{row['detail'] or ''}")
            with b2:
                if row["status"] != "resolved":
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        if st.button("Block", key=f"b_{row['id']}"):
                            update_alert_status(row["id"], "blocked")
                            log_audit("alert_block", row["id"])
                            st.rerun()
                    with c2:
                        if st.button("MFA", key=f"m_{row['id']}"):
                            update_alert_status(row["id"], "mfa_enforced")
                            log_audit("alert_mfa", row["id"])
                            st.rerun()
                    with c3:
                        if st.button("Ignore", key=f"i_{row['id']}"):
                            update_alert_status(row["id"], "ignored")
                            log_audit("alert_ignore", row["id"])
                            st.rerun()
                else:
                    st.caption(f"Status: **{row['status']}**")
            st.divider()


def page_dashboard():
    st.header("Security dashboard")
    ds = dashboard_series()
    if ds["total_analyses"] == 0:
        st.info("Ingest data to see risk trends and geography breakdowns.")
        return
    a1, a2, a3, a4 = st.columns(4)
    with a1:
        st.metric("Total analyses", ds["total_analyses"])
    with a2:
        st.metric("High severity (count)", ds["levels"].get("High", 0))
    with a3:
        st.metric("Medium", ds["levels"].get("Medium", 0))
    with a4:
        avg_r = sum(ds["risks"]) / len(ds["risks"]) if ds["risks"] else 0
        st.metric("Avg risk", f"{avg_r * 100:.1f}")

    c1, c2 = st.columns(2)
    with c1:
        tdf = pd.DataFrame({"t": pd.to_datetime(ds["times"], errors="coerce"), "risk": [x * 100 for x in ds["risks"]]})
        tdf = tdf.dropna(subset=["t"])
        if tdf.empty:
            st.caption("No valid timestamps for trend chart.")
        else:
            fig1 = px.line(
                tdf.sort_values("t"),
                x="t",
                y="risk",
                title="Risk trend over time",
                labels={"risk": "Risk (0–100)", "t": "Time"},
            )
            fig1.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(26,35,50,0.5)",
                font=dict(color="#e8eef4"),
            )
            st.plotly_chart(fig1, use_container_width=True)
    with c2:
        lv = ds["levels"]
        order = ["Low", "Medium", "High"]
        bar_x = [k for k in order if lv.get(k, 0) > 0]
        if not bar_x:
            bar_x = [k for k, v in lv.items() if v > 0] or list(lv.keys())
        bar_y = [lv[k] for k in bar_x]
        colors_map = {"Low": "#22c55e", "Medium": "#eab308", "High": "#ef4444"}
        bar_colors = [colors_map.get(k, "#94a3b8") for k in bar_x]
        fig2 = go.Figure(
            data=[go.Bar(x=bar_x, y=bar_y, marker_color=bar_colors)]
        )
        fig2.update_layout(
            title="Detections by threat level",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(26,35,50,0.5)",
            font=dict(color="#e8eef4"),
        )
        st.plotly_chart(fig2, use_container_width=True)

    c3, c4 = st.columns(2)
    with c3:
        loc = ds["loc_buckets"]
        if loc:
            fig3 = px.pie(
                names=list(loc.keys()),
                values=list(loc.values()),
                title="Login distance distribution",
                hole=0.45,
                color_discrete_sequence=px.colors.sequential.Teal_r,
            )
            fig3.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#e8eef4"))
            st.plotly_chart(fig3, use_container_width=True)
    with c4:
        analyses = fetch_analyses(80)
        types: dict[str, int] = {}
        for r in analyses:
            types[r["input_type"]] = types.get(r["input_type"], 0) + 1
        fig4 = go.Figure(
            data=[go.Bar(x=list(types.keys()), y=list(types.values()), marker_color="#6366f1")]
        )
        fig4.update_layout(
            title="Ingest by source type",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(26,35,50,0.5)",
            font=dict(color="#e8eef4"),
        )
        st.plotly_chart(fig4, use_container_width=True)

    st.subheader("User / behavior signals")
    st.caption("Synthetic demo: recipient volume vs. geo distance for recent analyses.")
    pts = []
    for r in analyses[:50]:
        try:
            f = json.loads(r["features_json"])
            pts.append(
                {
                    "recipients": f.get("recipient_count", 0),
                    "distance_km": f.get("location_distance_km", 0),
                    "risk": float(r["risk_score"]) * 100,
                    "level": r["threat_level"],
                }
            )
        except (json.JSONDecodeError, TypeError, KeyError):
            continue
    if pts:
        pdf = pd.DataFrame(pts)
        pdf["risk"] = pdf["risk"].clip(lower=1.0)
        fig5 = px.scatter(
            pdf,
            x="recipients",
            y="distance_km",
            color="level",
            size="risk",
            title="Recipients vs. geo distance (sized by risk)",
            color_discrete_map={"Low": "#22c55e", "Medium": "#eab308", "High": "#ef4444"},
        )
        fig5.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(26,35,50,0.5)",
            font=dict(color="#e8eef4"),
        )
        st.plotly_chart(fig5, use_container_width=True)


def page_admin():
    st.header("Admin")
    st.caption("Users, thresholds, audit trail — bonus points with judges.")
    thr = st.number_input(
        "Global risk threshold (0–1)",
        min_value=0.1,
        max_value=0.95,
        value=float(get_setting("risk_threshold", "0.55")),
        step=0.05,
    )
    if st.button("Save threshold"):
        set_setting("risk_threshold", str(thr))
        log_audit("settings", f"risk_threshold={thr}")
        st.success("Saved.")
    org = st.text_input("Organization display name", value=get_setting("org_name", "BEC Shield"))
    if st.button("Save org name"):
        set_setting("org_name", org)
        st.success("Saved.")

    st.subheader("Users")
    nu, nr = st.columns([3, 1])
    with nu:
        new_email = st.text_input("Add user email", placeholder="analyst@company.com")
    with nr:
        role = st.selectbox("Role", ["analyst", "admin"])
    if st.button("Add user") and new_email:
        try:
            add_user(new_email.strip(), role)
            log_audit("user_add", new_email)
            st.success("User added.")
        except Exception as e:
            st.error(str(e))
    users = fetch_users()
    st.dataframe(pd.DataFrame([row_to_dict(u) for u in users]), use_container_width=True)

    st.subheader("Audit log")
    aud = fetch_audit(60)
    st.dataframe(pd.DataFrame([row_to_dict(a) for a in aud]), use_container_width=True)


def main():
    st.set_page_config(
        page_title="BEC Shield | AI Detection",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_db()
    if "page" not in st.session_state:
        st.session_state.page = "landing"
    if "last_result" not in st.session_state:
        st.session_state.last_result = None
    if "processing" not in st.session_state:
        st.session_state.processing = False
    st.markdown(inject_global_css(), unsafe_allow_html=True)
    sidebar()
    page = st.session_state.page
    if page == "landing":
        page_landing()
    elif page == "input":
        page_input()
    elif page == "benchmarks":
        page_benchmarks()
    elif page == "processing":
        page_processing()
    elif page == "results":
        page_results()
    elif page == "alerts":
        page_alerts()
    elif page == "dashboard":
        page_dashboard()
    elif page == "admin":
        page_admin()
    st.markdown(
        '<p class="footer-note">BEC Shield — demo platform. Replace synthetic baselines with your SIEM / IdP for production.</p>',
        unsafe_allow_html=True,
    )


# Streamlit runs this file as __main__; guard avoids running the UI on `import app`.
if __name__ == "__main__":
    main()
