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

GHCARD = ('<div class="ghcard"><a class="ghbtn" href="https://github.com/trip-nine/flowtrim" target="_blank" rel="noopener"><svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38v-1.33c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.06-.49.06-.49.8.06 1.23.83 1.23.83.72 1.22 1.87.87 2.33.66.07-.52.28-.87.5-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg> trip-nine/flowtrim</a>'
          '<span>Source, releases and issues on GitHub. Clone with <code>git clone https://github.com/trip-nine/flowtrim.git</code></span></div>')

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
    # let Markdown inside HTML blocks (README's centered hero) render
    text = re.sub(r'<div align="center">', '<div align="center" class="hero" markdown="1">', text)
    # remote badge images are blocked by the page's content policy: render as local pills
    def badge(m):
        label, url = m.group(1), m.group(2)
        mm = re.search(r'badge/([^-]+(?:--[^-]+)*)-([^-]+(?:--[^-]+)*)-([0-9a-fA-F]{6}|[a-z]+)', url)
        if mm:
            k, v = mm.group(1).replace('--', '-'), mm.group(2).replace('--', '-')
            return f'<span class="badge"><b>{k}</b><i>{v}</i></span>'
        return f'<span class="badge"><b>{label}</b><i>passing</i></span>'
    text = re.sub(r'\[!\[([^\]]*)\]\((https://[^)]+)\)\]\([^)]*\)', badge, text)
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "toc", "sane_lists", "md_in_html"])
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
    body = render(path.read_text())
    if pid == "home":
        body = GHCARD + body
    sections.append(f'<section id="page-{pid}" class="page" hidden>{body}</section>')
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
.brand {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap }}
.ghbtn {{ margin-left:auto; display:inline-flex; align-items:center; gap:6px; text-decoration:none; color:var(--fg); border:1px solid var(--line); background:var(--code); border-radius:999px; padding:4px 12px; font-size:13px; font-weight:600 }}
.ghbtn:hover {{ border-color:var(--accent); color:var(--accent) }}
.ghcard {{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; border:1px solid var(--line); background:var(--code); border-radius:12px; padding:12px 16px; margin:14px 0 4px }}
.ghcard code {{ background:var(--bg) }}
.ghcard .ghbtn {{ margin-left:0; background:var(--bg) }}
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
.hero {{ text-align:center; padding:10px 0 6px }}
.hero h1 {{ font-size:2.2rem; margin:.3em 0 .2em }}
.hero p {{ max-width:760px; margin:.6em auto }}
.badge {{ display:inline-flex; margin:3px; font-size:12px; border-radius:6px; overflow:hidden; border:1px solid var(--line) }}
.badge b {{ background:#444; color:#fff; padding:2px 7px; font-weight:600 }}
.badge i {{ background:#6d5efc; color:#fff; padding:2px 7px; font-style:normal }}
.tablewrap {{ overflow-x:auto; margin:1em 0 }}
table {{ border-collapse:collapse; width:100%; font-size:14px }}
th, td {{ border-bottom:1px solid var(--line); padding:7px 10px; text-align:left; vertical-align:top }}
th {{ font-weight:600; background:var(--code) }}
blockquote {{ margin:1em 0; padding:.4em 1em; border-left:3px solid var(--accent); color:var(--muted); background:var(--code); border-radius:0 6px 6px 0 }}
.copy {{ float:right; font-size:12px; border:1px solid var(--line); background:var(--bg); color:var(--muted); border-radius:6px; padding:2px 8px; cursor:pointer }}
footer {{ color:var(--muted); font-size:12.5px; text-align:center; padding:30px 0 }}
</style></head>
<body>
<header><div class="brand">FlowTrim <span>docs · v0.3.0 · MIT</span><a class="ghbtn" href="https://github.com/trip-nine/flowtrim" target="_blank" rel="noopener"><svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38v-1.33c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.06-.49.06-.49.8.06 1.23.83 1.23.83.72 1.22 1.87.87 2.33.66.07-.52.28-.87.5-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg> View on GitHub</a></div><nav>{''.join(nav)}</nav></header>
<main>{''.join(sections)}
<footer>Generated from the repository's Markdown (README.md and docs/). Edit those files, not this page. · <a href="https://github.com/trip-nine/flowtrim" target="_blank" rel="noopener">github.com/trip-nine/flowtrim</a></footer></main>
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
document.addEventListener('click', e => {{
  const a = e.target.closest('[data-anchor]'); if (!a) return;
  const sec = a.closest('.page'); const t = sec && sec.querySelector('#' + CSS.escape(a.dataset.anchor));
  if (t) {{ e.preventDefault(); t.scrollIntoView({{behavior:'smooth', block:'start'}}); }}
}});
document.querySelectorAll('[data-anchor]').forEach(a => {{ a.style.cursor = 'pointer'; }});
addEventListener('hashchange', show); show();
</script>
</body></html>"""
out.write_text(page)
print(f"wrote {out} ({len(page)//1024} KiB)")
