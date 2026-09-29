# Stack playbook: PHP (plain PHP, Laravel, Symfony, WordPress)

Read this together with the class playbook. Check the PHP version (`composer.json` `require.php`,
Dockerfile): several sinks behave differently on PHP 5, 7 and 8.

## Sources
- Superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` (`name` and `type` are attacker-chosen), `$_SERVER['HTTP_*']`, `REQUEST_URI`, `QUERY_STRING`, `PHP_SELF`, `php://input`
- Laravel: `$request->input/get/query/all/only/except/route/file/header/cookie()`, `request()`, route model binding (the model is loaded, but not authorized)
- Symfony: `$request->query->get()`, `->request->get()`, `->attributes` (route params), `->headers`, `->getContent()`
- WordPress: `$_GET`/`$_POST` in `admin-ajax.php` actions (`wp_ajax_nopriv_*` handlers are unauthenticated), REST routes with `permission_callback => '__return_true'`, shortcode attributes (any contributor can set them)

## Sinks and what neutralises them
| Class | Sink | Safe pattern |
|---|---|---|
| SQL (CWE-89) | `mysqli_query` / `->query` / `pg_query` with concatenation, PDO `prepare(concat)`, Laravel `DB::select(concat)`, `whereRaw/orderByRaw/selectRaw`, `DB::raw`, Doctrine DQL strings, `$wpdb->query/get_results(concat)` | bound parameters, Eloquent/query builder with values, `$wpdb->prepare`, allowlists for identifiers |
| Command (CWE-78) | `system`, `exec`, `shell_exec`, `passthru`, backticks, `popen`, `proc_open`, `mail()` 5th parameter | `escapeshellarg` per argument; `proc_open` with an array (PHP 7.4+) |
| Code (CWE-94) | `eval`, `assert(string)` (PHP < 8), `create_function`, `preg_replace` with `/e` (PHP < 7), `call_user_func(input)`, variable functions `$f()` | allowlists |
| Inclusion (CWE-98) | `include/require(_once)` with input (LFI; RFI if `allow_url_include`), `php://filter` and `phar://` wrappers | fixed map from names to files |
| Path (CWE-22) | `file_get_contents`, `fopen`, `readfile`, `unlink`, `move_uploaded_file` destination, `Storage::get`, `response()->download` | `basename`, `realpath` + prefix check |
| Upload (CWE-434) | storing uploads under the web root with the client's extension; trusting `$_FILES['type']` | random names, extension allowlist, store outside web root |
| Deserialization (CWE-502) | `unserialize(input)` (POP chains through autoloaded classes), `phar://` paths passed to any file function (PHP < 8) | `json_decode`; `unserialize($x, ['allowed_classes' => false])` |
| XXE (CWE-611) | `simplexml_load_string/loadXML` with `LIBXML_NOENT`/`LIBXML_DTDLOAD`; `libxml_disable_entity_loader(false)` on PHP < 8 | default flags on PHP 8+ |
| SSRF (CWE-918) | `file_get_contents(url)`, `curl_setopt(CURLOPT_URL)`, Guzzle, `Http::get` | allowlist; `CURLOPT_PROTOCOLS` = HTTP(S) only; block private ranges |
| XSS (CWE-79) | `echo`/`print`/`<?=` of input, Blade `{!! !!}`, Twig `|raw`, `autoescape false` | `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`, Blade `{{ }}`, Twig default escaping, `esc_html`/`esc_attr` |
| Redirect / header (CWE-601/113) | `header("Location: " . $x)`, `redirect()->away($x)`, `wp_redirect` | relative paths; `wp_safe_redirect` |
| Variables (CWE-621) | `extract($_POST)`, `parse_str($x)` without a result array, `$$name` | explicit assignment |

## Type juggling and auth (CWE-697/287)
- Loose comparisons: `==`/`!=` with `"0e123..."` hashes (magic hashes), `in_array` without strict, `switch` on strings, `strcmp($a, [])` returning NULL (== 0) on PHP < 8. Password/token checks must use `hash_equals` or `password_verify`.
- JSON input lets a parameter be `true`, an integer or an array: `if ($input['pin'] == $stored)` with `true` passes on PHP < 8.
- Laravel: routes outside `auth` middleware groups; policies not called (`$this->authorize`); `$guarded = []` with `Model::create($request->all())` (mass assignment of `is_admin`).
- WordPress: AJAX/REST handlers must check `current_user_can(...)` **and** a nonce (`check_ajax_referer`); `is_admin()` only means "an admin page", not "an administrator".

## False-positive traps
- PDO/mysqli prepared statements with bound values; Eloquent `where('col', $value)`.
- Blade `{{ }}` and Twig `{{ }}` escape.
- `include __DIR__ . '/fixed.php'`.
- `intval()`/`(int)` casts before SQL or HTML output.
