# Playbook: access-control

**CWEs:** 862 missing authorization · 863 incorrect authorization · 639 IDOR · 285 · 287/306 missing or broken authentication · 347 JWT signature not verified · 352 CSRF · 384 session fixation · 640 weak password reset · 915 mass assignment

## Method
1. Build the route table: every handler with its method, path and the auth/role decorators or middleware that apply (include router-level and app-level middleware and their order).
2. For each handler that reads or modifies an object by identifier (`/notes/<id>`, `?user_id=`, body `owner_id`), check that the object is scoped to the caller (`WHERE owner_id = current_user.id`, or a policy check after load).
3. Compare sibling handlers: if `GET /x/<id>` checks ownership but `DELETE /x/<id>` doesn't, that is a finding.
4. Check authentication itself:
   - JWT: `verify=False`, `options={"verify_signature": False}`, `algorithms` including `none` or taken from the token header, HS/RS confusion, missing `exp` check
   - Session: predictable tokens, no rotation on login, secret key hardcoded or weak
   - Password reset: guessable tokens, tokens not bound to user or expiry, user enumeration
   - "Admin" flags read from the client (cookie, header, body)
5. Mass assignment: `Model(**request.json)`, `update(request.json)`, serializers with `fields="__all__"` on writable models that include `is_admin` / `role` / `owner_id`.
6. CSRF: state-changing cookie-authenticated endpoints without a CSRF token or SameSite protection; CSRF exemptions.

## False-positive traps
- Handlers behind global auth middleware; check how the middleware is registered before claiming "missing auth"
- Public-by-design endpoints (health, login, signup, static)
- Ownership enforced in the query (`get_object_or_404(Note, id=id, owner=request.user)`)
