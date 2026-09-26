"""
Requirement f: unified visibility across enterprise environments.

Generates ONE self-contained HTML file with the data embedded inline and
every chart drawn in plain SVG -- no server, no external JS library, no
CDN, no font download, nothing that needs the internet to render.
Consistent with the air-gap requirement: even the visibility layer works
with zero network access, you just open the file in a browser. The one
bit of interactivity (table search/sort) is plain inline JavaScript,
also with zero external dependencies.
"""
import html as _html
import json
from collections import Counter

_PALETTE = {
    "teal": "#2DD4BF", "coral": "#FB7185", "amber": "#FBBF24",
    "blue": "#60A5FA", "violet": "#A78BFA", "slate": "#8593AD",
}
_SERIES_COLORS = ["#60A5FA", "#A78BFA", "#2DD4BF", "#FBBF24", "#FB7185", "#818CF8", "#34D399", "#F472B6"]

# Actions get a fixed semantic color where we know what they mean; any
# other action value (a format can emit anything) gets a stable color
# hashed from its own name, so it's at least consistent across the
# donut, the legend and the table badges in a single render.
_ACTION_COLORS = {"allow": "teal", "deny": "coral", "auth": "violet", "unknown": "slate"}


def _color_for_action(action):
    key = _ACTION_COLORS.get(action)
    if key:
        return _PALETTE[key]
    return _SERIES_COLORS[hash(action) % len(_SERIES_COLORS)]


def _esc(v):
    return _html.escape(str(v)) if v is not None else ""


def _donut_chart(counter, title, size=190, stroke=26):
    items = counter.most_common(6)
    total = sum(c for _, c in items)
    if not total:
        return f'<div class="panel"><h3>{title}</h3><p class="empty">No data</p></div>'
    r = (size - stroke) / 2
    cx = cy = size / 2
    circumference = 2 * 3.14159265 * r
    offset = 0
    segments = []
    legend = []
    for label, count in items:
        frac = count / total
        color = _color_for_action(label)
        dash = frac * circumference
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" stroke-dasharray="{dash:.2f} {circumference - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})">'
            f'<title>{_esc(label)}: {count:,} ({frac*100:.1f}%)</title></circle>'
        )
        offset += dash
        legend.append(
            f'<div class="legend-row"><span class="swatch" style="background:{color}"></span>'
            f'<span class="legend-label">{_esc(label)}</span>'
            f'<span class="legend-val">{count:,} &middot; {frac*100:.1f}%</span></div>'
        )
    return f'''
    <div class="panel">
      <h3>{title}</h3>
      <div class="donut-row">
        <svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" class="donut">
          {''.join(segments)}
          <text x="{cx}" y="{cy - 4}" text-anchor="middle" class="donut-total">{total:,}</text>
          <text x="{cx}" y="{cy + 16}" text-anchor="middle" class="donut-total-label">events</text>
        </svg>
        <div class="legend">{''.join(legend)}</div>
      </div>
    </div>'''


def _hbar_chart(counter, title, color, max_items=8, width=460):
    items = counter.most_common(max_items)
    if not items:
        return f'<div class="panel"><h3>{title}</h3><p class="empty">No data</p></div>'
    max_count = max(c for _, c in items)
    row_h, gap, label_w = 24, 10, 150
    height = len(items) * (row_h + gap)
    track_w = width - label_w - 60
    bars = []
    for i, (label, count) in enumerate(items):
        y = i * (row_h + gap)
        bar_w = max(2, (count / max_count) * track_w)
        short = (label[:20] + "…") if len(label) > 21 else label
        bars.append(f'''
          <text x="0" y="{y + row_h/2 + 4}" class="bar-label">{_esc(short)}<title>{_esc(label)}</title></text>
          <rect x="{label_w}" y="{y + 3}" width="{track_w}" height="{row_h - 6}" rx="4" class="bar-track"/>
          <rect x="{label_w}" y="{y + 3}" width="{bar_w:.1f}" height="{row_h - 6}" rx="4" fill="{color}">
            <title>{_esc(label)}: {count:,}</title></rect>
          <text x="{label_w + track_w + 8}" y="{y + row_h/2 + 4}" class="bar-count">{count:,}</text>
        ''')
    return f'''
    <div class="panel">
      <h3>{title}</h3>
      <svg viewBox="0 0 {width} {height}" width="100%" height="{height}">{''.join(bars)}</svg>
    </div>'''


def _year_chart(year_counts, title="Events by year", color=_PALETTE["blue"], width=460, height=150):
    if not year_counts:
        return f'<div class="panel"><h3>{title}</h3><p class="empty">No dated events</p></div>'
    years = sorted(year_counts.keys())
    max_count = max(year_counts.values())
    n = len(years)
    plot_h = height - 30
    bar_w = min(46, (width - 20) / max(n, 1) - 8)
    gap = (width - 20 - bar_w * n) / max(n - 1, 1) if n > 1 else 0
    bars = []
    for i, y in enumerate(years):
        count = year_counts[y]
        h = max(2, (count / max_count) * plot_h)
        x = 10 + i * (bar_w + gap)
        by = plot_h - h
        bars.append(f'''
          <rect x="{x:.1f}" y="{by:.1f}" width="{bar_w:.1f}" height="{h:.1f}" rx="3" fill="{color}">
            <title>{y}: {count:,} events</title></rect>
          <text x="{x + bar_w/2:.1f}" y="{plot_h + 18}" text-anchor="middle" class="bar-count">{y}</text>
        ''')
    return f'''
    <div class="panel">
      <h3>{title}</h3>
      <p class="panel-note">Normalized to one consistent ISO-8601 timestamp regardless of each
      source's original shape -- see timestamp_utils.py.</p>
      <svg viewBox="0 0 {width} {height}" width="100%" height="{height}">{''.join(bars)}</svg>
    </div>'''


def _confidence_bar(buckets, width=460):
    order = [("high", "≥0.8", "teal"), ("medium", "0.4–0.8", "amber"), ("low", "<0.4", "coral")]
    total = sum(buckets.values())
    if not total:
        return '<div class="panel"><h3>Confidence distribution</h3><p class="empty">No data</p></div>'
    segs, legend, x = [], [], 0
    for key, range_label, color_key in order:
        count = buckets.get(key, 0)
        if not count:
            continue
        w = (count / total) * width
        segs.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="20" fill="{_PALETTE[color_key]}">'
                     f'<title>{key} ({range_label}): {count:,} ({100*count/total:.1f}%)</title></rect>')
        legend.append(f'<div class="legend-row"><span class="swatch" style="background:{_PALETTE[color_key]}">'
                       f'</span><span class="legend-label">{key} confidence ({range_label})</span>'
                       f'<span class="legend-val">{count:,} &middot; {100*count/total:.1f}%</span></div>')
        x += w
    return f'''
    <div class="panel">
      <h3>Confidence distribution</h3>
      <svg viewBox="0 0 {width} 20" width="100%" height="20" class="conf-bar">
        <rect x="0" y="0" width="{width}" height="20" rx="6" fill="none"/>
        {''.join(segs)}
      </svg>
      <div class="legend" style="margin-top:10px;">{''.join(legend)}</div>
    </div>'''


class DashboardAggregator:
    """
    Accumulates exactly the numbers the dashboard needs, one event at a
    time, in O(1) memory regardless of how many events are fed in.

    This replaces the old approach of materializing the entire event
    list (`events = list(events)`) purely to count things and slice the
    first 25 rows -- at GB-scale input (millions of events) that full
    materialization is the actual memory ceiling, not the parsing engine
    itself, which already streams. Feed events into `.add(event)` one
    at a time as they're produced; nothing is ever kept except a handful
    of Counters and a capped 25-row sample.
    """

    def __init__(self, sample_size=25):
        self.total = 0
        self.action_counts = Counter()
        self.format_counts = Counter()
        self.vendor_counts = Counter()
        self.src_ip_counts = Counter()
        self.conf_buckets = Counter()
        self.year_counts = Counter()
        self.confidence_sum = 0.0
        self.sample_size = sample_size
        self.sample_rows = []

    def add(self, event):
        self.total += 1
        self.action_counts[event.get("action") or "unknown"] += 1
        self.format_counts[event.get("source_format") or "unknown"] += 1
        self.vendor_counts[event.get("vendor") or "unknown"] += 1
        src_ip = event.get("src_ip")
        if src_ip:
            self.src_ip_counts[src_ip] += 1
        c = event.get("confidence") or 0
        self.confidence_sum += c
        bucket = "high" if c >= 0.8 else "medium" if c >= 0.4 else "low"
        self.conf_buckets[bucket] += 1
        ts = event.get("timestamp")
        if ts and len(ts) >= 4 and ts[:4].isdigit():
            self.year_counts[ts[:4]] += 1
        if len(self.sample_rows) < self.sample_size:
            self.sample_rows.append(event)


_TABLE_COLUMNS = [
    ("timestamp", "Timestamp", "text"), ("vendor", "Vendor", "text"),
    ("source_format", "Format", "text"), ("action", "Action", "text"),
    ("src_ip", "Src IP", "text"), ("dst_ip", "Dst IP", "text"),
    ("confidence", "Confidence", "num"),
]


def render_dashboard(agg, out_path, title="ULPF Unified Visibility Dashboard"):
    """Renders the HTML dashboard from an already-populated DashboardAggregator.
    Use this directly when you're accumulating events in a larger streaming
    loop (see run_demo.py) so events are never buffered a second time just
    for the dashboard."""
    total = agg.total
    denies = agg.action_counts.get("deny", 0)
    deny_rate = (100 * denies / total) if total else 0
    avg_conf = (agg.confidence_sum / total) if total else 0

    rows_html = []
    for e in agg.sample_rows:
        action = e.get("action") or "unknown"
        cells = "".join(
            f'<td data-sort="{_esc(e.get(k))}">{_esc(e.get(k))}</td>'
            if k != "action" else
            f'<td data-sort="{_esc(action)}"><span class="tag" style="--tag-color:{_color_for_action(action)}">'
            f'{_esc(action)}</span></td>'
            for k, _, _ in _TABLE_COLUMNS
        )
        rows_html.append(f"<tr>{cells}</tr>")

    header_cells = "".join(
        f'<th data-col="{i}" data-type="{typ}">{label}<span class="sort-arrow"></span></th>'
        for i, (_, label, typ) in enumerate(_TABLE_COLUMNS)
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{_esc(title)}</title>
<style>
  :root {{
    --bg: #0B1220; --panel: #121B2E; --panel-raised: #17233A; --border: #22304A;
    --text: #E7ECF5; --text-muted: #8593AD; --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }}
  @media (prefers-color-scheme: light) {{
    :root:not([data-theme="dark"]) {{
      --bg: #F6F7FB; --panel: #FFFFFF; --panel-raised: #F0F2F8; --border: #E1E5EF;
      --text: #14192B; --text-muted: #5B6478;
    }}
  }}
  :root[data-theme="light"] {{
    --bg: #F6F7FB; --panel: #FFFFFF; --panel-raised: #F0F2F8; --border: #E1E5EF;
    --text: #14192B; --text-muted: #5B6478;
  }}
  * {{ box-sizing: border-box; }}
  html {{ scroll-padding-top: env(safe-area-inset-top, 0px); }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 28px 32px calc(40px + env(safe-area-inset-bottom, 0px));
    padding-top: calc(28px + env(safe-area-inset-top, 0px));
    font-variant-numeric: tabular-nums;
  }}
  .masthead {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;
               flex-wrap: wrap; margin-bottom: 22px; }}
  .masthead h1 {{ font-size: 19px; font-weight: 650; margin: 0 0 4px 0; letter-spacing: -0.01em; }}
  .masthead .meta {{ color: var(--text-muted); font-size: 13px; }}
  .badge {{ font-size: 12px; color: #2DD4BF; border: 1px solid #2DD4BF44; background: #2DD4BF14;
            padding: 4px 10px; border-radius: 6px; white-space: nowrap; }}
  .theme-btn {{ border: 1px solid var(--border); background: var(--panel); color: var(--text-muted);
                border-radius: 6px; padding: 4px 10px; font-size: 12px; cursor: pointer; }}
  .theme-btn:hover {{ color: var(--text); }}
  .hero {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
           padding: 22px 26px; margin-bottom: 18px; border-top: 3px solid #60A5FA; }}
  .hero .num {{ font-size: 42px; font-weight: 700; line-height: 1; font-family: var(--mono); }}
  .hero .label {{ color: var(--text-muted); font-size: 13px; margin-top: 8px; }}
  .kpi-strip {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 18px; }}
  .kpi {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px;
          flex: 1 1 200px; }}
  .kpi .num {{ font-size: 21px; font-weight: 650; font-family: var(--mono); }}
  .kpi .label {{ color: var(--text-muted); font-size: 12px; margin-top: 4px; }}
  .grid {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 18px; }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px;
            flex: 1 1 440px; }}
  .panel h3 {{ font-size: 13px; font-weight: 600; margin: 0 0 12px 0; }}
  .panel-note {{ font-size: 11px; color: var(--text-muted); margin: -8px 0 10px 0; }}
  .empty {{ color: var(--text-muted); font-size: 13px; }}
  svg text {{ fill: var(--text); font-size: 12px; font-family: inherit; }}
  .bar-label {{ fill: var(--text-muted); }}
  .bar-count {{ fill: var(--text-muted); font-family: var(--mono); }}
  .bar-track {{ fill: var(--panel-raised); }}
  .donut-total {{ font-size: 20px; font-weight: 700; font-family: var(--mono); }}
  .donut-total-label {{ font-size: 10px; fill: var(--text-muted); }}
  .donut-row {{ display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }}
  .legend {{ display: flex; flex-direction: column; gap: 7px; flex: 1; min-width: 160px; }}
  .legend-row {{ display: flex; align-items: center; gap: 8px; font-size: 12px; }}
  .swatch {{ width: 9px; height: 9px; border-radius: 2px; flex-shrink: 0; }}
  .legend-label {{ flex: 1; }}
  .legend-val {{ color: var(--text-muted); font-family: var(--mono); }}
  .table-panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
                  overflow: hidden; }}
  .table-panel-head {{ display: flex; justify-content: space-between; align-items: center;
                        padding: 14px 18px; border-bottom: 1px solid var(--border); gap: 12px; flex-wrap: wrap; }}
  .table-panel-head h3 {{ font-size: 13px; font-weight: 600; margin: 0; }}
  #search {{ background: var(--panel-raised); border: 1px solid var(--border); color: var(--text);
             border-radius: 6px; padding: 7px 10px; font-size: 12px; width: 220px; }}
  .table-scroll {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; font-family: var(--mono); }}
  th {{ text-align: left; padding: 9px 14px; background: var(--panel-raised); color: var(--text-muted);
        font-weight: 600; white-space: nowrap; cursor: pointer; user-select: none; border-bottom: 1px solid var(--border); }}
  th:hover {{ color: var(--text); }}
  .sort-arrow {{ margin-left: 4px; opacity: 0.5; }}
  td {{ padding: 8px 14px; border-bottom: 1px solid var(--border); white-space: nowrap; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px;
          color: var(--tag-color); background: color-mix(in srgb, var(--tag-color) 16%, transparent);
          border: 1px solid color-mix(in srgb, var(--tag-color) 40%, transparent); }}
  @media (max-width: 860px) {{
    .grid .panel, .kpi-strip .kpi {{ flex-basis: 100%; }}
    body {{ padding: 20px 16px; }}
  }}
</style>
</head>
<body>
  <div class="masthead">
    <div>
      <h1>{_esc(title)}</h1>
      <div class="meta">Generated from {total:,} normalized events &middot; {len(agg.vendor_counts)} vendors &middot; {len(agg.format_counts)} source formats</div>
    </div>
    <div style="display:flex; gap:8px; align-items:center;">
      <span class="badge">offline &mdash; no network calls</span>
      <button class="theme-btn" onclick="toggleTheme()" id="themeBtn">dark / light</button>
    </div>
  </div>

  <div class="hero">
    <div class="num">{total:,}</div>
    <div class="label">total events normalized across every onboarded source</div>
  </div>

  <div class="kpi-strip">
    <div class="kpi"><div class="num">{avg_conf:.2f}</div><div class="label">avg. parser confidence</div></div>
    <div class="kpi"><div class="num">{deny_rate:.1f}%</div><div class="label">denied / blocked events</div></div>
    <div class="kpi"><div class="num">{len(agg.src_ip_counts):,}</div><div class="label">unique source IPs seen</div></div>
    <div class="kpi"><div class="num">{len(agg.year_counts)}</div><div class="label">distinct years covered</div></div>
  </div>

  <div class="grid">
    {_donut_chart(agg.action_counts, "Events by action")}
    {_confidence_bar(agg.conf_buckets)}
    {_hbar_chart(agg.format_counts, "Events by source format", _PALETTE["violet"])}
    {_hbar_chart(agg.vendor_counts, "Events by vendor", _PALETTE["blue"])}
    {_hbar_chart(agg.src_ip_counts, "Top source IPs", _PALETTE["coral"])}
    {_year_chart(agg.year_counts)}
  </div>

  <div class="table-panel">
    <div class="table-panel-head">
      <h3>Sample of normalized events (first {len(agg.sample_rows)} of {total:,})</h3>
      <input id="search" type="text" placeholder="Filter rows…" oninput="filterRows()">
    </div>
    <div class="table-scroll">
      <table id="eventTable">
        <thead><tr>{header_cells}</tr></thead>
        <tbody>{''.join(rows_html)}</tbody>
      </table>
    </div>
  </div>

<script>
  function toggleTheme() {{
    var r = document.documentElement;
    var cur = r.getAttribute('data-theme');
    r.setAttribute('data-theme', cur === 'dark' ? 'light' : 'dark');
  }}
  function filterRows() {{
    var q = document.getElementById('search').value.toLowerCase();
    var rows = document.querySelectorAll('#eventTable tbody tr');
    rows.forEach(function(r) {{
      r.style.display = r.textContent.toLowerCase().indexOf(q) === -1 ? 'none' : '';
    }});
  }}
  (function() {{
    var state = {{}};
    document.querySelectorAll('#eventTable th').forEach(function(th) {{
      th.addEventListener('click', function() {{
        var col = th.getAttribute('data-col'), type = th.getAttribute('data-type');
        var asc = !(state[col] === 'asc');
        state = {{}}; state[col] = asc ? 'asc' : 'desc';
        document.querySelectorAll('#eventTable th .sort-arrow').forEach(function(a) {{ a.textContent = ''; }});
        th.querySelector('.sort-arrow').textContent = asc ? ' \u25B2' : ' \u25BC';
        var tbody = document.querySelector('#eventTable tbody');
        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
        rows.sort(function(a, b) {{
          var av = a.children[col].getAttribute('data-sort') || '';
          var bv = b.children[col].getAttribute('data-sort') || '';
          if (type === 'num') {{ av = parseFloat(av) || 0; bv = parseFloat(bv) || 0; return asc ? av - bv : bv - av; }}
          return asc ? av.localeCompare(bv) : bv.localeCompare(av);
        }});
        rows.forEach(function(r) {{ tbody.appendChild(r); }});
      }});
    }});
  }})();
</script>
</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html)
    return out_path


def generate_dashboard(events, out_path, title="ULPF Unified Visibility Dashboard"):
    """Convenience wrapper: builds the dashboard from any iterable of events
    in a single streaming pass (no full-list materialization). Kept for
    callers (tests, small ad-hoc runs) that just have one iterable and
    don't need to share it with other writers. For the main pipeline run,
    prefer driving a shared DashboardAggregator directly -- see run_demo.py."""
    agg = DashboardAggregator()
    for event in events:
        agg.add(event)
    return render_dashboard(agg, out_path, title=title)
