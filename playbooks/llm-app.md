# Playbook: llm-app (applications that call LLMs)

Based on the OWASP Top 10 for LLM Applications. **CWEs:** 94 (model output executed) · 78/89/79 via model output · 1427 prompt injection · 862 excessive agency · 200/359 sensitive data disclosure · 918 SSRF via tools · 770 unbounded consumption

## Core question
Treat model output as attacker-controlled whenever any untrusted text reaches the prompt (user
messages, retrieved documents, web pages, emails, tickets, file contents, tool results). Then look
for places where that output gets power.

## Sinks for model output (insecure output handling)
- `eval` / `exec` / `subprocess` / SQL built from completions ("generate a query", "run this command")
- HTML rendering of completions without escaping (XSS in chat UIs), and Markdown image rendering that can exfiltrate data through URLs
- Tool or function calls: which tools exist, whether arguments are validated, and whether destructive tools (delete, send email, pay, write file, HTTP fetch) run without human confirmation
- Agents with file-system or network tools scoped wider than needed (path traversal or SSRF through tool arguments)

## Prompt construction
- Untrusted content concatenated into the system prompt or instructions without delimiting or role separation
- Secrets, API keys or other users' data placed in prompts (disclosure through the model)
- Retrieval (RAG) over documents from other tenants without access filtering (cross-tenant leakage)

## Resource and supply-chain issues
- No max tokens, rate limit or loop bound on agent iterations (cost DoS)
- Loading models with pickle-based formats from untrusted sources (`torch.load`, `joblib`), and `trust_remote_code=True`

A finding needs a concrete chain: which untrusted text enters, how it steers the model, and which
unguarded capability it reaches.
