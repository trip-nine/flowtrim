#!/usr/bin/env python3
"""Render README + docs/*.md into one self-contained HTML docs page.

Usage: python3 -I tools/build_docs_site.py <repo_dir> <out.html>
Mermaid blocks are rendered client-side (mermaid from cdn.jsdelivr.net).
"""
import html
import re
import sys
from pathlib import Path

import markdown

repo = Path(sys.argv[1])
out = Path(sys.argv[2])

PAGES = [
    ("home", "Home", repo / "README.md"),
    ("quick", "0 · Quick start", repo / "docs/00-quickstart.md"),
    ("overview", "1 · Overview", repo / "docs/01-overview.md"),
    ("setup", "2 · Setup", repo / "docs/02-setup.md"),
    ("guide", "3 · User guide", repo / "docs/03-user-guide.md"),
    ("config", "4 · Configuration", repo / "docs/04-configuration.md"),
    ("enrich", "5 · Enrichment", repo / "docs/05-enrichment.md"),
    ("demo", "Demo package", repo / "demo/README.md"),
    ("rules", "Rules playbook", repo / "docs/RULES.md"),
    ("plan", "Plan & unknowns", repo / "docs/PLAN.md"),
    ("bench", "Benchmarks", repo / "docs/BENCHMARKS.md"),
]
link_map = {p.name: pid for pid, _, p in PAGES}
link_map["../README.md"] = "home"


def render(text: str) -> str:
    blocks = []

    def stash(m):
        blocks.append(m.group(1))
        return f"\n\nMERMAIDBLOCK{len(blocks) - 1}\n\n"

    text = re.sub(r"```mermaid\n(.*?)```", stash, text, flags=re.S)
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "toc", "sane_lists"])
    for i, b in enumerate(blocks):
        body = body.replace(f"<p>MERMAIDBLOCK{i}</p>", f'<pre class="mermaid">{html.escape(b)}</pre>')

    # rewrite links between docs to in-page hashes
    def relink(m):
        href = m.group(1)
        path, _, frag = href.partition("#")
        name = path.split("/")[-1]
        if path in link_map:
            return f'href="#{link_map[path]}"'
        if name in link_map and path.endswith(".md"):
            return f'href="#{link_map[name]}"'
        if path.startswith(("http://", "https://")):
            return f'href="{href}" target="_blank" rel="noopener"'
        if not path and frag:
            return 'data-anchor="' + frag + '"'
        return f'href="https://github.com/trip-nine/flowtrim/blob/main/{path.lstrip("./")}" target="_blank" rel="noopener"'

    body = re.sub(r'src="(?:\.\./)?(?:docs/)?img/', 'src="img/', body)
    return re.sub(r'href="([^"]+)"', relink, body)


sections = []
nav = []
for pid, title, path in PAGES:
    sections.append(f'<section id="page-{pid}" class="page" hidden>{render(path.read_text())}</section>')
    nav.append(f'<a href="#{pid}" data-page="{pid}">{html.escape(title)}</a>')

page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlowTrim documentation</title>
<style>
:root {{ --bg:#fbfbf9; --fg:#1d1d1b; --muted:#6b6b66; --line:#e4e3dd; --accent:#c2410c; --code:#f2f1ec; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#161614; --fg:#ecebe6; --muted:#a3a29b; --line:#2e2d29; --accent:#fb923c; --code:#22211e; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15.5px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif; }}
header {{ position:sticky; top:0; z-index:5; background:var(--bg); border-bottom:1px solid var(--line); }}
.brand {{ padding:12px 20px 4px; font-weight:700; letter-spacing:.2px }}
.brand span {{ color:var(--muted); font-weight:500; margin-left:8px; font-size:13px }}
nav {{ display:flex; gap:4px; overflow-x:auto; padding:6px 14px 10px; scrollbar-width:none }}
nav a {{ white-space:nowrap; text-decoration:none; color:var(--muted); padding:5px 11px; border-radius:999px; font-size:13.5px; border:1px solid transparent }}
nav a.active {{ color:var(--fg); border-color:var(--line); background:var(--code) }}
main {{ max-width:960px; margin:0 auto; padding:18px 20px 80px }}
h1 {{ font-size:1.75rem; line-height:1.25; margin:.6em 0 .5em }}
h2 {{ font-size:1.3rem; margin:1.8em 0 .5em; padding-top:.4em; border-top:1px solid var(--line) }}
h3 {{ font-size:1.08rem; margin:1.4em 0 .4em }}
a {{ color:var(--accent) }}
code {{ background:var(--code); padding:.1em .35em; border-radius:4px; font-size:.88em; font-family:ui-monospace, SFMono-Regular, Menlo, monospace }}
pre {{ background:var(--code); padding:12px 14px; border-radius:8px; overflow-x:auto; font-size:13px; line-height:1.45 }}
pre code {{ background:none; padding:0 }}
pre.mermaid {{ background:transparent; text-align:center; padding:8px 0 }}
img {{ max-width:100%; height:auto; border:1px solid var(--line); border-radius:10px }}
.tablewrap {{ overflow-x:auto; margin:1em 0 }}
table {{ border-collapse:collapse; width:100%; font-size:14px }}
th, td {{ border-bottom:1px solid var(--line); padding:7px 10px; text-align:left; vertical-align:top }}
th {{ font-weight:600; background:var(--code) }}
blockquote {{ margin:1em 0; padding:.4em 1em; border-left:3px solid var(--accent); color:var(--muted); background:var(--code); border-radius:0 6px 6px 0 }}
.copy {{ float:right; font-size:12px; border:1px solid var(--line); background:var(--bg); color:var(--muted); border-radius:6px; padding:2px 8px; cursor:pointer }}
footer {{ color:var(--muted); font-size:12.5px; text-align:center; padding:30px 0 }}
</style></head>
<body>
<header><div class="brand">FlowTrim <span>docs · v0.3.0 · MIT</span></div><nav>{''.join(nav)}</nav></header>
<main>{''.join(sections)}
<footer>Generated from the repository's Markdown (README.md and docs/). Edit those files, not this page.</footer></main>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>
const dark = matchMedia('(prefers-color-scheme: dark)').matches;
try {{ mermaid.initialize({{ startOnLoad:false, theme: dark ? 'dark' : 'neutral', securityLevel:'strict' }}); }} catch (e) {{}}
const rendered = new Set();
document.querySelectorAll('table').forEach(t => {{ const w = document.createElement('div'); w.className='tablewrap'; t.parentNode.insertBefore(w, t); w.appendChild(t); }});
document.querySelectorAll('pre > code').forEach(c => {{
  const b = document.createElement('button'); b.className='copy'; b.textContent='Copy';
  b.onclick = () => navigator.clipboard.writeText(c.innerText).then(() => {{ b.textContent='Copied'; setTimeout(() => b.textContent='Copy', 1500); }}).catch(() => {{ b.textContent='Select & copy'; }});
  c.parentNode.insertBefore(b, c);
}});
function show() {{
  const id = (location.hash || '#home').slice(1);
  const target = document.getElementById('page-' + id) ? id : 'home';
  document.querySelectorAll('.page').forEach(p => p.hidden = p.id !== 'page-' + target);
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('active', a.dataset.page === target));
  if (!rendered.has(target) && window.mermaid) {{
    rendered.add(target);
    mermaid.run({{ nodes: document.querySelectorAll('#page-' + target + ' pre.mermaid') }}).catch(() => {{}});
  }}
  window.scrollTo(0, 0);
}}
addEventListener('hashchange', show); show();
</script>
</body></html>"""
out.write_text(page)
print(f"wrote {out} ({len(page)//1024} KiB)")
