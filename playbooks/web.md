# Playbook: web

**CWEs:** 22 path traversal · 918 SSRF · 79 XSS · 601 open redirect · 611 XXE · 434 unrestricted upload · 942 permissive CORS · 1021 clickjacking (low) · 400/1333 ReDoS · 20 validation gaps with security impact

## Path traversal (CWE-22)
Sinks: `open`, `send_file`, `send_from_directory` (safe by design), `os.path.join(base, user)` (an absolute `user` replaces base!), `res.sendFile`, `fs.readFile`, `Files.readAllBytes`, `ZipFile.extractall` / tar extraction (zip slip).
Safe pattern: `realpath(join(base, name))` followed by a prefix check against `realpath(base)` + `os.sep`, or `secure_filename`, or an ID-to-path lookup.

## SSRF (CWE-918)
Sinks: `requests.*`, `urllib`, `httpx`, `fetch`, `axios`, `HttpClient`, `curl_exec`, image, PDF or webhook fetchers, and URL previews.
Check: is the scheme, host or port attacker-controlled? Is there an allowlist enforced *after* DNS resolution? Are redirects followed? Can it reach `169.254.169.254`, localhost or internal ranges?

## XSS (CWE-79)
Sinks: `Markup(`, `|safe`, `{% autoescape false %}`, `render_template_string` with input, `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `document.write`, returning `text/html` responses built from input.
Frameworks auto-escape by default (Jinja2 in Flask, React, Django templates), so only report when escaping is bypassed or the context is JS, URL or attribute.

## Open redirect (CWE-601)
`redirect(request.args["next"])` without a same-origin or allowlist check.

## XXE (CWE-611)
`lxml.etree.parse` with `resolve_entities=True` or a custom parser, `xml.dom.minidom` / `sax` on untrusted input (Python ≥3.7.1 is safe by default for external entities), Java `DocumentBuilderFactory` without `disallow-doctype-decl`.

## Uploads (CWE-434)
User-controlled filename or extension stored under the web root, content type trusted, no size limit.

## CORS
`Access-Control-Allow-Origin` reflecting the request `Origin` together with `Allow-Credentials: true`.
