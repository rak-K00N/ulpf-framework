"""
Requirement f: unified visibility across enterprise environments.

Generates ONE self-contained HTML file with the data embedded inline and
charts drawn in plain SVG -- no server, no external JS library, no CDN,
nothing that needs the internet to render. Consistent with the air-gap
requirement: even the visibility layer works with zero network access,
you just open the file in a browser.
"""
import json
from collections import Counter
from html import escape


def _svg_bar_chart(counter, title, width=520, bar_height=28, color="#3b82f6"):
    items = counter.most_common(8)
    if not items:
        return f"<p>No data for {title}</p>"
    max_count = max(c for _, c in items)
    height = len(items) * (bar_height + 10) + 50
    bars = []
    for i, (label, count) in enumerate(items):
        y = 40 + i * (bar_height + 10)
        bar_w = int((count / max_count) * (width - 180))
        bars.append(f'''
          <text x="0" y="{y + bar_height/2 + 5}" font-size="13" fill="#333">{escape(str(label))}</text>
          <rect x="150" y="{y}" width="{bar_w}" height="{bar_height}" fill="{color}" rx="4"/>
          <text x="{150 + bar_w + 8}" y="{y + bar_height/2 + 5}" font-size="13" fill="#333">{count}</text>
        ''')
    return f'''
    <div class="chart-card">
      <h3>{title}</h3>
      <svg viewBox="0 0 {width} {height}" width="100%" height="{height}">
        {''.join(bars)}
      </svg>
    </div>'''


def generate_dashboard(events, out_path, title="ULPF Unified Visibility Dashboard"):
    events = list(events)
    total = len(events)

    action_counts = Counter(e.get("action") or "unknown" for e in events)
    format_counts = Counter(e.get("source_format") or "unknown" for e in events)
    vendor_counts = Counter(e.get("vendor") or "unknown" for e in events)
    src_ip_counts = Counter(e.get("src_ip") for e in events if e.get("src_ip"))

    conf_buckets = Counter()
    for e in events:
        c = e.get("confidence") or 0
        conf_buckets["high (>=0.8)" if c >= 0.8 else "medium (0.4-<0.8)" if c >= 0.4 else "low (<0.4)"] += 1

    denies = action_counts.get("deny", 0)
    allows = action_counts.get("allow", 0)

    sample_rows = events[:25]
    table_rows = "".join(
      f"<tr><td>{escape(str(e.get('timestamp')))}</td>"
      f"<td>{escape(str(e.get('vendor')))}</td>"
      f"<td>{escape(str(e.get('source_format')))}</td>"
      f"<td class='action-{escape(str(e.get('action')))}'>"
      f"{escape(str(e.get('action')))}</td>"
      f"<td>{escape(str(e.get('src_ip')))}</td>"
      f"<td>{escape(str(e.get('dst_ip')))}</td>"
      f"<td>{escape(str(e.get('confidence')))}</td></tr>"
      for e in sample_rows
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #f4f5f7; margin: 0; padding: 24px; color: #1a1a1a; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .subtitle {{ color: #666; margin-bottom: 24px; font-size: 14px; }}
  .stat-row {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat-card {{ background: white; border-radius: 10px; padding: 16px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); min-width: 140px; }}
  .stat-card .num {{ font-size: 26px; font-weight: 700; }}
  .stat-card .label {{ font-size: 12px; color: #666; margin-top: 4px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
  .chart-card {{ background: white; border-radius: 10px; padding: 16px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  .chart-card h3 {{ font-size: 14px; margin: 0 0 12px 0; color: #333; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  th, td {{ text-align: left; padding: 8px 12px; font-size: 12px; border-bottom: 1px solid #eee; }}
  th {{ background: #fafafa; color: #666; text-transform: uppercase; font-size: 11px; }}
  .action-allow {{ color: #16a34a; font-weight: 600; }}
  .action-deny {{ color: #dc2626; font-weight: 600; }}
  .action-auth {{ color: #7c3aed; font-weight: 600; }}
  .offline-badge {{ display: inline-block; background: #ecfdf5; color: #16a34a; font-size: 11px; padding: 4px 10px; border-radius: 999px; margin-bottom: 16px; }}
</style>
</head>
<body>
  <h1>{title}</h1>
  <div class="subtitle">Generated from {total:,} normalized events across all onboarded sources.</div>
  <div class="offline-badge">&#9679; fully offline &mdash; no external scripts, no network calls</div>

  <div class="stat-row">
    <div class="stat-card"><div class="num">{total:,}</div><div class="label">TOTAL EVENTS</div></div>
    <div class="stat-card"><div class="num">{allows:,}</div><div class="label">ALLOWED</div></div>
    <div class="stat-card"><div class="num">{denies:,}</div><div class="label">DENIED</div></div>
    <div class="stat-card"><div class="num">{len(vendor_counts)}</div><div class="label">VENDORS SEEN</div></div>
    <div class="stat-card"><div class="num">{len(format_counts)}</div><div class="label">SOURCE FORMATS</div></div>
  </div>

  <div class="grid">
    {_svg_bar_chart(action_counts, "Events by action", color="#3b82f6")}
    {_svg_bar_chart(format_counts, "Events by source format", color="#8b5cf6")}
    {_svg_bar_chart(vendor_counts, "Events by vendor", color="#f59e0b")}
    {_svg_bar_chart(src_ip_counts, "Top source IPs", color="#ef4444")}
  </div>

  {_svg_bar_chart(conf_buckets, "Confidence distribution", color="#10b981")}

  <h3 style="margin-top:24px;">Sample of normalized events (first 25)</h3>
  <table>
    <tr><th>Timestamp</th><th>Vendor</th><th>Format</th><th>Action</th><th>Src IP</th><th>Dst IP</th><th>Confidence</th></tr>
    {table_rows}
  </table>
</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html)
    return out_path
