"""Write scan findings as a self-contained HTML report."""
from html import escape
from urllib.parse import urlparse

from reports.guidance import remediation_for


def _safe_link(value: object) -> str:
    url = str(value or "")
    if urlparse(url).scheme not in ("http", "https"):
        return ""
    return url


def write(results: dict, path: str) -> None:
    findings = []
    for finding in results.get("findings", []):
        severity = escape(str(finding.get("severity", "info")))
        title = escape(str(finding.get("title", "Untitled finding")))
        module = escape(str(finding.get("module", "Unknown module")))
        detail = escape(str(finding.get("detail", "")))
        guidance = escape(remediation_for(str(finding.get("module", ""))))
        confidence = finding.get("confidence")
        confidence_text = (
            f"{escape(str(confidence))}%"
            if isinstance(confidence, (int, float))
            else "Not rated"
        )
        reference_url = _safe_link(finding.get("reference"))
        reference = (
            f'<a href="{escape(reference_url, quote=True)}" '
            'rel="noreferrer noopener">Advisory</a>'
            if reference_url else "—"
        )
        findings.append(
            "<tr>"
            f'<td><span class="severity {severity.lower()}">{severity}</span></td>'
            f"<td>{module}</td><td>{title}</td><td>{detail}</td>"
            f"<td>{confidence_text}</td><td>{guidance}</td><td>{reference}</td>"
            "</tr>"
        )

    target = escape(str(results.get("target", "")))
    scan_time = escape(str(results.get("scan_time", "")))
    rows = "\n".join(findings) or (
        '<tr><td colspan="7">No findings were reported.</td></tr>'
    )
    errors = []
    for error in results.get("errors", []):
        module = escape(str(error.get("module", "Unknown module")))
        error_type = escape(str(error.get("error_type", "Error")))
        message = escape(str(error.get("message", "")))
        errors.append(f"<li><strong>{module} ({error_type}):</strong> {message}</li>")
    errors_section = (
        "<section><h2>Checks that failed</h2><ul>"
        + "".join(errors)
        + "</ul></section>"
        if errors else ""
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cronos scan report</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
    body {{ max-width: 1440px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: .75rem; margin: 1rem 0; }}
    .card {{ border: 1px solid #8886; border-radius: .5rem; padding: .7rem 1rem; min-width: 8rem; }}
    .toolbar {{ display: flex; gap: .75rem; align-items: center; margin: 1rem 0; }}
    input, select {{ font: inherit; padding: .45rem; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #8886; padding: .65rem; text-align: left; vertical-align: top; }}
    th {{ position: sticky; top: 0; background: Canvas; }}
    .severity {{ font-weight: 700; }}
    .critical, .high {{ color: #b3261e; }}
    .medium {{ color: #8a4b00; }}
    @media (prefers-color-scheme: dark) {{
      .critical, .high {{ color: #ff8a80; }}
      .medium {{ color: #ffd180; }}
    }}
  </style>
</head>
<body>
  <h1>Cronos scan report</h1>
  <p><strong>Target:</strong> {target}</p>
  <p><strong>Scan time:</strong> {scan_time}</p>
  <section class="summary" aria-label="Finding counts">
    <div class="card"><strong>Total findings</strong><br>{len(results.get("findings", []))}</div>
    <div class="card"><strong>Critical</strong><br>{sum(f.get("severity") == "critical" for f in results.get("findings", []))}</div>
    <div class="card"><strong>High</strong><br>{sum(f.get("severity") == "high" for f in results.get("findings", []))}</div>
    <div class="card"><strong>Medium</strong><br>{sum(f.get("severity") == "medium" for f in results.get("findings", []))}</div>
    <div class="card"><strong>Check errors</strong><br>{len(results.get("errors", []))}</div>
  </section>
  {errors_section}
  <div class="toolbar">
    <label for="severity-filter">Filter severity</label>
    <select id="severity-filter">
      <option value="">All</option><option>critical</option><option>high</option>
      <option>medium</option><option>low</option><option>info</option>
    </select>
    <label for="search">Search findings</label>
    <input id="search" type="search" placeholder="Module or text">
    <span id="visible-count" aria-live="polite"></span>
  </div>
  <div class="table-wrap">
  <table id="findings">
    <thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Details</th><th>Signal confidence</th><th>Remediation guidance</th><th>Reference</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  </div>
  <script>
    const severity = document.querySelector("#severity-filter");
    const search = document.querySelector("#search");
    const rows = [...document.querySelectorAll("#findings tbody tr")];
    function updateRows() {{
      let visible = 0;
      for (const row of rows) {{
        const matchesSeverity = !severity.value || row.cells[0].textContent.trim().toLowerCase() === severity.value;
        const matchesText = row.textContent.toLowerCase().includes(search.value.toLowerCase());
        row.hidden = !(matchesSeverity && matchesText);
        if (!row.hidden && !row.cells[0].hasAttribute("colspan")) visible++;
      }}
      document.querySelector("#visible-count").textContent = `${{visible}} shown`;
    }}
    severity.addEventListener("change", updateRows);
    search.addEventListener("input", updateRows);
    updateRows();
  </script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as report:
        report.write(document)
