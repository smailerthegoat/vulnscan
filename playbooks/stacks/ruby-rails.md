# Stack playbook: Ruby (Rails, Sinatra)

Read this together with the class playbook. Check the Rails version (`Gemfile.lock`) first: several
defaults changed across 5.x, 6.x and 7.x.

## Sources
- `params` (query, form, JSON body and route segments all merge into it), `cookies` (unsigned ones), `request.headers`, `request.env`, `request.body`/`raw_post`, `request.referer`, uploaded file `original_filename`
- `cookies.signed`/`cookies.encrypted` and `session` are integrity-protected only if `secret_key_base` is secret (check `config/secrets.yml`, `credentials.yml.enc` handling, `SECRET_KEY_BASE` defaults)
- Background jobs (Sidekiq/ActiveJob) arguments come from whoever enqueued them

## Sinks and what neutralises them
| Class | Sink | Safe pattern |
|---|---|---|
| SQL (CWE-89) | string conditions with interpolation: `where("x = #{...}")`, `order(params[:sort])`, `pluck`, `select`, `group`, `joins`, `from`, `find_by_sql`, `connection.execute`, `exists?(params[:id])` (hash/array forms) | hash conditions `where(name: x)`, placeholders `where("name = ?", x)`, `sanitize_sql_*`, allowlists for column/direction |
| Command (CWE-78) | `system("... #{x}")`, backticks, `%x()`, `exec`, `IO.popen(string)`, `Open3.*(string)`, **`Kernel#open(input)`** (a leading `\|` runs a command) and `URI.open` on old open-uri | array form `system("cmd", arg)`, `Shellwords.escape`, `File.open`/`URI.parse(...).open` |
| Code (CWE-94/470) | `eval`, `instance_eval`, `send(params[:m])`, `public_send`, `params[:type].constantize`, `Object.const_get` | allowlist the method/class names |
| SSTI (CWE-1336) | `render inline: input`, `ERB.new(input).result` | render fixed templates with locals |
| Path (CWE-22) | `send_file`, `File.read/open`, `render file:` with input, `Rails.root.join("x", input)` (a leading `/` escapes!) | `File.basename`, `File.expand_path` + `start_with?(base)` |
| SSRF (CWE-918) | `Net::HTTP`, `HTTParty`, `Faraday`, `RestClient`, `URI.open` with input | host allowlist after resolution; `ssrf_filter` gem |
| Redirect (CWE-601) | `redirect_to params[:url]`, `redirect_to request.referer` | Rails 7 `raise_on_open_redirects`; `redirect_to(x, allow_other_host: false)`; only paths |
| XSS (CWE-79) | `.html_safe`, `raw`, `<%== %>`, `render html:/text:` with input, `link_to name, params[:url]` (`javascript:` URLs), `content_tag` with `html_safe` attrs | ERB `<%= %>` escapes by default; `sanitize` with an allowlist |
| Deserialization (CWE-502) | `Marshal.load`, `YAML.load` on Psych < 4 (Ruby < 3.1), `Oj.load` in object mode, cookie serializer `:marshal` with a known secret | `JSON.parse`, `YAML.safe_load` |
| Mass assignment (CWE-915) | `params.permit!`, `permit(:role, :admin, ...)` on user-editable forms, `attr_accessible` apps (Rails < 4) | narrow `permit` lists |

## Auth and access control
- `before_action :authenticate_user!` with `only:`/`except:` lists: new actions are often missing from them; `skip_before_action` in subclasses.
- Devise/Pundit/CanCanCan: controllers without `authorize`/`load_and_authorize_resource`; `verify_authorized` not enforced.
- IDOR: `Model.find(params[:id])` instead of `current_user.models.find(params[:id])`.
- CSRF: `protect_from_forgery` missing or `skip_forgery_protection` / `null_session` on cookie-authenticated controllers.
- Routes: `match ... via: :all`, and `get` routes that change state (CSRF-exempt by method).

## False-positive traps
- `where(name: params[:name])`, `find(params[:id])` (cast to the key type), `find_by(email: x)`.
- `<%= %>` output, `content_tag(:p, input)` and `link_to input, path` (the text part) are escaped.
- `system("cmd", arg)` with separate arguments has no shell.
- `YAML.load` on Psych 4+ (Ruby 3.1+) is `safe_load` by default.
