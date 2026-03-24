def inject_global_css() -> str:
    return """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [class*="css"] { font-family: 'DM Sans', system-ui, sans-serif !important; }
h1, h2, h3 { letter-spacing: -0.02em; }
.hero-wrap {
  background: linear-gradient(135deg, rgba(34,211,238,0.12) 0%, rgba(99,102,241,0.08) 50%, rgba(15,20,25,0) 100%);
  border: 1px solid rgba(148,163,184,0.15);
  border-radius: 20px;
  padding: 2.5rem 2rem;
  margin-bottom: 1.5rem;
}
.hero-title {
  font-size: 2.35rem;
  font-weight: 700;
  background: linear-gradient(90deg, #e8eef4 0%, #22d3ee 45%, #a5b4fc 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.tagline { color: #94a3b8; font-size: 1.1rem; margin-top: 0.5rem; }
.pipeline {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
  justify-content: center;
  padding: 1.25rem;
  background: rgba(26,35,50,0.6);
  border-radius: 14px;
  border: 1px solid rgba(148,163,184,0.12);
  margin: 1rem 0;
}
.pipe-step {
  background: rgba(34,211,238,0.1);
  color: #22d3ee;
  padding: 0.45rem 0.85rem;
  border-radius: 999px;
  font-size: 0.85rem;
  font-weight: 600;
}
.pipe-arrow { color: #64748b; font-weight: bold; }
.metric-card {
  background: linear-gradient(180deg, rgba(26,35,50,0.95) 0%, rgba(15,20,25,0.9) 100%);
  border: 1px solid rgba(148,163,184,0.12);
  border-radius: 16px;
  padding: 1.25rem 1.5rem;
  text-align: center;
}
.risk-ring {
  font-family: 'JetBrains Mono', monospace;
  font-size: 2.75rem;
  font-weight: 700;
}
.footer-note { color: #64748b; font-size: 0.8rem; margin-top: 2rem; }
div[data-testid="stSidebarNav"] { display: none; }
section[data-testid="stSidebar"] { border-right: 1px solid rgba(148,163,184,0.1); }
.stButton button {
  border-radius: 10px !important;
  font-weight: 600 !important;
}
</style>
"""


def pipeline_html() -> str:
    steps = [
        "Data input",
        "Preprocessing",
        "Rule engine",
        "ML (Isolation Forest)",
        "Risk scoring",
    ]
    inner = ""
    for i, s in enumerate(steps):
        inner += f'<span class="pipe-step">{s}</span>'
        if i < len(steps) - 1:
            inner += '<span class="pipe-arrow">↓</span>'
    return f'<div class="pipeline">{inner}</div>'
