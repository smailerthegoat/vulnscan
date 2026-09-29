# Playbook: deserialization-config

**CWEs:** 502 unsafe deserialization · 915 · 489/215 debug features in production · 1188 insecure defaults · 16 misconfiguration · 532 secrets in logs · 209 stack traces to users

## Unsafe deserialization (usually RCE)
- Python: `pickle.load(s)`, `cPickle`, `dill`, `shelve`, `jsonpickle.decode`, `yaml.load` with `Loader=yaml.Loader` / `UnsafeLoader` / `FullLoader` (older PyYAML), `torch.load` without `weights_only=True`, `joblib.load`, `numpy.load(allow_pickle=True)` on untrusted files
- Java: `ObjectInputStream.readObject`, XStream without allowlist, Jackson default typing, SnakeYAML `new Yaml()` (pre-2.0)
- .NET: `BinaryFormatter`, `TypeNameHandling.All`
- PHP: `unserialize` of user input
- Node: `node-serialize`, `funcster`, `vm` with object revival
- Ruby: `Marshal.load`, `YAML.load` (Psych < 4)

Report only when the bytes can come from an attacker: request body, uploaded file, cookie, cache or queue shared with lower-trust writers, or a downloaded model or artifact.
Safe variants: `yaml.safe_load`, `json`, `torch.load(weights_only=True)`, allowlisted class resolvers.

## Configuration
- `app.run(debug=True)`, `DEBUG = True` in production settings, Werkzeug debugger exposed (this is RCE), stack traces returned to clients
- Binding admin or debug servers to `0.0.0.0`
- Permissive defaults: `ALLOWED_HOSTS = ["*"]` combined with host-header-dependent logic, `SESSION_COOKIE_SECURE = False` on HTTPS apps, disabled CSRF middleware
- Infrastructure-as-code in the repo: public buckets, `0.0.0.0/0` on admin ports, privileged containers, secrets in Dockerfiles or CI YAML

Debug mode counts only if it is enabled on a deployable path by default, not behind an env flag that defaults to off.
