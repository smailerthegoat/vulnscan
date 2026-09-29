# Playbook: injection

**CWEs:** 78/77 OS command · 89 SQL · 943 NoSQL · 94/95 code/eval · 1336 template (SSTI) · 90 LDAP · 643 XPath · 113 header/CRLF

## Sinks to enumerate first
- **SQL:** `execute(`, `executemany`, `raw(`, `extra(`, `text(`, `query(`, `$queryRawUnsafe`, `createQuery`, `Statement.execute*`, string-built `WHERE`/`ORDER BY`/`LIMIT`
- **NoSQL:** `$where`, `$regex` from input, `find(json.loads(user))`, operator injection via dict or JSON bodies (`{"$ne": null}`)
- **Shell:** `os.system`, `subprocess.*(shell=True)`, `popen`, `child_process.exec/execSync`, `Runtime.exec(String)`, backticks, `system()`, `proc_open`
- **Code:** `eval`, `exec`, `compile`, `Function(`, `vm.runIn*`, `setTimeout(string)`, `pickle`-free "expression evaluators", `ScriptEngine`
- **Templates:** `render_template_string`, `Template(user)`, `Environment().from_string`, `ejs.render(user)`, server-side template compile of input

## Sources
Request params, body, headers, cookies, path params, uploaded file names and contents, env passed by
callers, CLI args (only if the tool runs with privileges or on behalf of others), queue messages,
DB values originally written by users (second-order), and LLM output.

## What neutralises it (check before reporting)
- Bound parameters or placeholders; ORM filter kwargs; query builders with value binding
- `subprocess.run([list], shell=False)`, as long as the program itself isn't attacker-chosen and argument injection (`--flag`) is ruled out
- Strict allowlists (e.g. column name ∈ fixed set), `int()` coercion, regex `fullmatch` on a safe charset
- Identifiers (table and column names) cannot be bound, so string-built identifiers need an allowlist

## Common false-positive traps
- f-string SQL whose interpolated parts are constants or allowlisted
- `shell=True` with a fully constant command
- `eval` on a literal or on trusted config at build time
- Test fixtures and migrations
