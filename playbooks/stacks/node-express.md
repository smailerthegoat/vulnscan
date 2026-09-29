# Stack playbook: Node.js / TypeScript (Express, Fastify, Koa, NestJS, Next.js, Remix) and front-ends

Read this together with the class playbook.

## Sources
- Express/Fastify: `req.query`, `req.params`, `req.body`, `req.cookies`, `req.headers`, `req.get()`, `req.files`/`req.file` (multer: `originalname` is attacker-chosen)
- Koa: `ctx.query`, `ctx.params`, `ctx.request.body`, `ctx.headers`
- NestJS: `@Query()`, `@Param()`, `@Body()`, `@Headers()`; DTO classes validate only if a global `ValidationPipe` is installed (with `whitelist: true` to strip extra fields)
- Next.js: API routes `req.query/body`; route handlers `request.nextUrl.searchParams`, `await request.json()`, `formData()`; server actions (every argument is client-controlled); `params` in dynamic routes
- Type confusion: with `express.json()` or `qs` parsing (`?a[b]=1`), any field can be an object or array, not a string. `typeof` checks matter.

## Sinks and what neutralises them
| Class | Sink | Safe pattern |
|---|---|---|
| SQL (CWE-89) | `db.query(concat)`, sqlite `all/get/run(template)`, knex `raw/whereRaw`, Sequelize `query`/`literal`, Prisma `$queryRawUnsafe`, TypeORM `query`/`where(string)` | placeholders; Prisma tagged `$queryRaw\`...${x}\`` is parameterized; `Sequelize.escape` |
| NoSQL (CWE-943) | `Model.find(req.body)`, `findOne({user: req.body.user})` where the value can be `{"$ne": null}`, `$where` with input | cast with `String()`, schema validation, `mongo-sanitize`, `sanitizeFilter` (Mongoose 6+) |
| Command (CWE-78) | `child_process.exec/execSync(string)`, `spawn(cmd, args, {shell: true})`, `shelljs.exec` | `execFile`/`spawn` with a fixed program and an args array |
| Code (CWE-94) | `eval`, `new Function`, `vm.runIn*` (the `vm` module is not a sandbox), `setTimeout(string)` | never evaluate input |
| SSTI (CWE-1336) | `ejs.render(input)`, `pug.compile(input)`, `Handlebars.compile(input)`, `_.template(input)`; `res.render(view, req.query)` (EJS `settings`/`outputFunctionName` option pollution) | fixed templates; pass data, not options |
| Path (CWE-22) | `fs.readFile(path.join(base, input))`, `res.sendFile(input)` without `root`, `res.download`, `express.static` with symlinks, archive extraction | `path.basename`, or `path.resolve` + `startsWith(base + path.sep)`; `sendFile(name, {root})` |
| SSRF (CWE-918) | `fetch/axios/got/http.get(input)`, webhook and image-proxy features | host allowlist after DNS resolution, block private ranges, disable redirects |
| Redirect (CWE-601) | `res.redirect(req.query.next)` | relative paths only (reject `//` and `/\`) |
| XSS (CWE-79) | `res.send(string)` (text/html), template `<%- %>` (EJS unescaped), `!{}` (Pug), `{{{ }}}` (Handlebars), React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`, DOM `innerHTML` from `location` | escape by context; `res.json`; DOMPurify |
| Prototype pollution (CWE-1321) | recursive merge/clone/set of user objects (`_.merge` < 4.17.12, custom `deepMerge`, `obj[a][b] = v`) | block `__proto__`/`constructor`/`prototype` keys, `Object.create(null)`, `Map` |
| Deserialization (CWE-502) | `node-serialize.unserialize`, `funcster`, js-yaml `load` < 4 with custom types | `JSON.parse` |
| ReDoS (CWE-1333) | `new RegExp(input)`, catastrophic backtracking regexes applied to input | escape, `re2`, length limits |

## Auth and access control
- Middleware order: `app.use(auth)` only guards routes registered after it; routers mounted before it are public. Check `router.use` per router and NestJS `@UseGuards` at controller vs method level, and global guards in `main.ts`/`APP_GUARD`.
- JWT (`jsonwebtoken`): `jwt.decode()` never verifies; `verify` without `algorithms` on old versions allows `none`/HS-RS confusion; secrets hardcoded or from `process.env.X || "secret"`.
- Sessions: `express-session` with a hardcoded secret, `cookie: {secure: false}` on HTTPS, no regeneration on login.
- Next.js middleware matchers (`config.matcher`) often miss routes; server actions need their own auth checks.
- IDOR: `Model.findById(req.params.id)` without comparing the owner to `req.user`.

## False-positive traps
- Parameterized `db.query(sql, [values])`; Prisma/TypeORM repository methods with objects.
- `res.json()` and `res.send(object)` send JSON, not HTML.
- React/Vue/Angular templates escape by default.
- `execFile('git', ['log', input])` has no shell.
