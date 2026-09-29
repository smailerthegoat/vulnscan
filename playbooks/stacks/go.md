# Stack playbook: Go (net/http, gorilla/mux, chi, gin, echo, fiber)

Read this together with the class playbook. It lists where attacker input enters a Go service, which
sinks matter, and which framework defaults already protect you.

## Sources
- `net/http`: `r.FormValue`, `r.PostFormValue`, `r.URL.Query()`, `r.URL.Path`, `r.PathValue` (Go 1.22 mux), `r.Header`, `r.Cookie`, `r.Body` (`json.NewDecoder(r.Body).Decode(&x)`)
- Routers: `mux.Vars(r)`, `chi.URLParam(r, ...)`, gin `c.Query/Param/PostForm/GetHeader/ShouldBind*`, echo `c.QueryParam/Param/Bind`, fiber `c.Query/Params/BodyParser`
- gRPC handlers: every field of the request message; Protobuf types give no validation
- Struct binding (`ShouldBindJSON(&dto)`) makes every exported field attacker-controlled; binding tags like `binding:"required"` don't sanitize

## Sinks and what neutralises them
| Class | Sink | Safe pattern |
|---|---|---|
| SQL (CWE-89) | `db.Query/Exec/QueryRow(fmt.Sprintf(...))`, gorm `Raw`, `Where(string)`, `Order(input)` | `?`/`$1` placeholders; gorm `Where("name = ?", x)` or struct/map conditions; allowlist for ORDER BY |
| Command (CWE-78) | `exec.Command("sh", "-c", input)`, `exec.Command(input)` | fixed program, input as separate argv entries; watch for `--flag` argument injection |
| Path (CWE-22) | `os.Open/ReadFile/Create`, `http.ServeFile`, gin `c.File`, `filepath.Join(base, input)` | `filepath.Base`, or `filepath.Clean("/"+p)` then join, or `strings.HasPrefix(filepath.Clean(full), base+"/")`; `http.FileServer(http.Dir(x))` is safe |
| Archive (CWE-22) | `zip.Reader`/`tar.Reader` entry names joined to a dest dir (zip slip) | reject names with `..` after `filepath.Clean`; check prefix |
| SSRF (CWE-918) | `http.Get(input)`, `http.NewRequest(m, input, ...)`, custom `Transport` | allowlist host; resolve and block private/loopback/link-local IPs in a `DialContext` hook; redirects follow by default (`CheckRedirect`) |
| Redirect (CWE-601) | `http.Redirect(w, r, input, ...)`, `c.Redirect(302, input)` | relative paths only; reject `//host` and `/\host` |
| XSS (CWE-79) | `fmt.Fprintf(w, input)` (net/http sniffs `text/html`), `template.HTML(input)`, `text/template` used for HTML | `html/template` auto-escapes by context; set `Content-Type: text/plain` or JSON |
| SSTI | `template.New(...).Parse(input)` | never parse user-supplied templates |
| TLS (CWE-295) | `tls.Config{InsecureSkipVerify: true}` | only in tests |

## Auth and access control
- Middleware order matters: `r.Use(auth)` only applies to routes registered after it on that router; subrouters (`r.PathPrefix(...).Subrouter()`, gin `Group`) must attach middleware themselves. Compare the route table with the groups that carry auth.
- JWT (`golang-jwt/jwt`): check the key func verifies `token.Method` (alg confusion) and that `Parse` errors aren't ignored; `ParseUnverified` never authenticates.
- IDOR: handlers that load by `id` from the path must scope by the caller (`WHERE id = ? AND owner_id = ?`).

## Concurrency and memory
- Data races on maps or package-level state shared across handlers (`concurrent map writes` panics = DoS; torn auth state).
- `io.ReadAll(r.Body)` without `http.MaxBytesReader` → memory DoS; big `json.Decoder` payloads likewise.
- `unsafe` and cgo code: apply the memory-safety playbook.

## False-positive traps
- `database/sql` placeholders; values passed as extra args are bound.
- `exec.Command("git", "log", input)` has no shell; only argument injection (inputs starting with `-`) is possible.
- `html/template` escapes; only `template.HTML/JS/URL` conversions bypass it.
- `http.FileServer(http.Dir(...))` rejects `..` itself.
