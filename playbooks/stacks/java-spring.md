# Stack playbook: Java / Kotlin (Spring Boot, Spring MVC, Servlets, JAX-RS)

Read this together with the class playbook.

## Sources
- Parameters of `@GetMapping/@PostMapping/@RequestMapping/...` handlers: `@RequestParam`, `@PathVariable`, `@RequestBody` (every DTO field, nested objects too), `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, and un-annotated simple parameters (bound from the query string implicitly)
- Servlet API: `request.getParameter*`, `getHeader`, `getQueryString`, `getRequestURI`, `getPathInfo`, `getCookies`, `getInputStream`, `getReader`, `getPart`, `MultipartFile.getOriginalFilename()`
- JAX-RS: `@QueryParam`, `@PathParam`, `@FormParam`, `@HeaderParam`, entity parameters
- Messaging: `@KafkaListener`, `@RabbitListener`, `@JmsListener` payloads (trust depends on who can publish)

## Sinks and what neutralises them
| Class | Sink | Safe pattern |
|---|---|---|
| SQL (CWE-89) | `Statement.execute*`, `prepareStatement(concat)`, `JdbcTemplate.query/update(concat)`, `EntityManager.createQuery/createNativeQuery(concat)`, `@Query(nativeQuery=true)` with SpEL `#{...}` concatenation, jOOQ `DSL.field(String)` | bind params (`?`, `:name`), Spring Data derived queries, Criteria API; allowlist column names for `ORDER BY` / `Sort.by(input)` |
| Expression (CWE-917) | `SpelExpressionParser.parseExpression(input)`, `@Value`/`@PreAuthorize` built from input, OGNL, MVEL | never evaluate input; `SimpleEvaluationContext` limits damage |
| Template (CWE-1336) | a `@Controller` returning a view name built from input (Thymeleaf `__${...}__` preprocessing → RCE), Velocity/FreeMarker templates from input | fixed view names; `@ResponseBody` or `redirect:` prefixes aren't view resolution |
| Deserialization (CWE-502) | `ObjectInputStream.readObject`, XStream `fromXML`, SnakeYAML `new Yaml().load` (< 2.0), Jackson `enableDefaultTyping`/`@JsonTypeInfo(use = Id.CLASS)`, `XMLDecoder` | JSON to fixed DTOs; `ObjectInputFilter` allowlists; SnakeYAML `SafeConstructor` |
| XXE (CWE-611) | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SAXReader` without disabling DTDs | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| Command (CWE-78) | `Runtime.exec(String)`, `ProcessBuilder("sh","-c",input)` | argv arrays with a fixed program |
| Path (CWE-22) | `new File(base, input)`, `Paths.get(base, input)`, `Path.resolve(input)`, `FileSystemResource`, `ZipEntry.getName()` (zip slip) | `normalize()` + `startsWith(base)` on the real path; `FilenameUtils.getName` |
| SSRF (CWE-918) | `RestTemplate`, `WebClient.uri(input)`, `new URL(input).openConnection()`, `HttpClient`, Jsoup | host allowlist enforced after DNS resolution; redirects |
| Redirect (CWE-601) | `response.sendRedirect(input)`, `"redirect:" + input`, `RedirectView` | relative paths or allowlist |
| Log4Shell class (CWE-917) | user data logged through log4j-core 2.0–2.14.1 with lookups enabled | check the resolved log4j-core version |

## Auth and access control (Spring Security)
- Read the `SecurityFilterChain` (or `WebSecurityConfigurerAdapter`): `permitAll()` matchers, matcher order (first match wins), `antMatchers` vs `mvcMatchers` mismatches (`/admin` vs `/admin/`), `csrf().disable()` on cookie-authenticated apps.
- Method security needs `@EnableMethodSecurity`/`@EnableGlobalMethodSecurity`; without it `@PreAuthorize` does nothing. `@Secured` on a private method or on a self-invoked method is bypassed (proxy-based).
- IDOR: `repository.findById(id)` in a handler without an owner check; Spring Data REST exposes repositories as endpoints automatically (`@RepositoryRestResource`).
- Mass assignment: binding request bodies straight to JPA entities exposes `role`, `enabled`, `owner` fields; `@ModelAttribute` binds every setter unless `@InitBinder` sets allowed fields.
- Actuator: `management.endpoints.web.exposure.include=*` exposes `/actuator/env`, `/heapdump` (secrets) and sometimes `/jolokia` (RCE).

## False-positive traps
- `JdbcTemplate.query("... ?", args)` and JPQL with `:param` are bound.
- Numeric handler parameters (`Long id`, `int page`) can't carry injection.
- Thymeleaf `th:text` escapes; only `th:utext` and view-name construction are dangerous.
- Jackson without default typing and without polymorphic `Id.CLASS` is safe.
