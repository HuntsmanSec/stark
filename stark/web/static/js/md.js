// Minimal, safe Markdown renderer (HTML is always escaped first).
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function inline(text) {
  const codes = [];
  let s = text.replace(/``\s?(.+?)\s?``|`([^`]+)`/g, (_, a, b) => { codes.push(a ?? b); return `\u0000${codes.length - 1}\u0000`; });
  s = esc(s);
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, t, u) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${t}</a>`);
  s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/(^|[^\w*])\*(?!\s)(.+?)\*(?!\w)/g, "$1<em>$2</em>")
       .replace(/(^|[^\w])_(?!\s)(.+?)_(?!\w)/g, "$1<em>$2</em>");
  s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${esc(codes[+i])}</code>`);
  return s;
}

function splitRow(line) {
  let l = line.trim(); if (l.startsWith("|")) l = l.slice(1); if (l.endsWith("|") && !l.endsWith("\\|")) l = l.slice(0, -1);
  const cells = []; let cur = ""; let inCode = false;
  for (let i = 0; i < l.length; i++) {
    const ch = l[i];
    if (ch === "`") inCode = !inCode;
    if (ch === "\\" && l[i + 1] === "|") { cur += "|"; i++; continue; }
    if (ch === "|" && !inCode) { cells.push(cur.trim()); cur = ""; continue; }
    cur += ch;
  }
  cells.push(cur.trim());
  return cells;
}

export function renderMarkdown(src) {
  const lines = (src || "").replace(/\r\n/g, "\n").split("\n");
  const out = []; let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      const buf = []; i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++; out.push(`<pre><code>${esc(buf.join("\n"))}</code></pre>`); continue;
    }
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) { out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`); i++; continue; }
    if (/^\s*(---|\*\*\*)\s*$/.test(line)) { out.push("<hr>"); i++; continue; }
    if (/^\s*\|/.test(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      const head = splitRow(line); i += 2; const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(splitRow(lines[i++]));
      const showHead = head.some((c) => c);
      out.push(`<table>${showHead ? `<thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead>` : ""}<tbody>${
        rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      const buf = []; while (i < lines.length && /^\s*>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^\s*>\s?/, ""));
      out.push(`<blockquote>${inline(buf.join(" "))}</blockquote>`); continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      const ordered = /^\s*\d+\./.test(line); const items = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        let item = lines[i++].replace(/^\s*([-*]|\d+\.)\s+/, "");
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*]|\d+\.)\s+/.test(lines[i])) item += " " + lines[i++].trim();
        items.push(`<li>${inline(item)}</li>`);
      }
      out.push(ordered ? `<ol>${items.join("")}</ol>` : `<ul>${items.join("")}</ul>`); continue;
    }
    if (!line.trim()) { i++; continue; }
    const buf = [line]; i++;
    while (i < lines.length && lines[i].trim() && !/^(#{1,6}\s|```|\s*\||\s*([-*]|\d+\.)\s|\s*>)/.test(lines[i])) buf.push(lines[i++]);
    out.push(`<p>${inline(buf.join(" "))}</p>`);
  }
  return out.join("\n");
}
