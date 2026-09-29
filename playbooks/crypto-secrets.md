# Playbook: crypto-secrets

**CWEs:** 798 hardcoded credentials · 321 hardcoded key · 327/328 broken or weak algorithm · 916 weak password hashing · 330/338 weak randomness · 295 TLS verification disabled · 326 short keys · 329 static IV · 208 timing-unsafe compare

## Secrets
- Assignments to names like `secret`, `password`, `token`, `api_key`, `private_key`, `SECRET_KEY`, and connection strings with credentials.
- Report only if it looks real and is used by shipped code (not `changeme`, `example`, `xxx`, test fixtures, or `.env.example`). Session-signing keys hardcoded in the app config count (session forgery).
- Never copy a full secret value into the evidence. Copy the line but keep your description generic.

## Crypto misuse
- Passwords hashed with md5, sha1 or sha256 without a KDF → use bcrypt, scrypt, argon2 or PBKDF2 with a high iteration count.
- md5 or sha1 used for **security** decisions (signatures, integrity against attackers). md5 for cache keys or ETags is **not** a finding.
- ECB mode, static or zero IVs, reused nonces with GCM or CTR, RSA without OAEP, keys under 2048 bits (RSA).
- `random` / `Math.random` / `rand()` used to create tokens, passwords, reset codes or session ids → use `secrets` / `crypto.randomBytes`. Randomness for UI shuffles or sampling is not a finding.
- Token or HMAC comparisons with `==` instead of `hmac.compare_digest` (low unless remotely measurable).

## Transport
`verify=False`, `ssl._create_unverified_context`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `CERT_NONE`, a trust-all `TrustManager`. The severity depends on what flows over the connection.
