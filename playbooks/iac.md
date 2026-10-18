# Playbook: iac

**CWEs:** 732/284 over-broad access · 250 runs as root / privileged · 311/319 unencrypted storage or transport · 798 secrets in config · 1104/829 unpinned third-party code · 78/94 CI script injection · 778 logging disabled

Infrastructure findings are configuration, not data flow: the "source" is who can reach the resource, the "sink" is
what the setting exposes. Confirm that the file is deployed (not an example or a test fixture) and that no other
layer overrides the setting (a module default, an org policy, a later manifest). `p/terraform`, `p/dockerfile`,
`p/kubernetes` and `p/github-actions` leads arrive as scanner candidates; your job is reachability and impact.

## Terraform (cloud resources)
- Public exposure: S3 `acl = "public-read"`, missing `aws_s3_bucket_public_access_block`, `0.0.0.0/0` ingress on
  22, 3389, database or admin ports, `publicly_accessible = true` on databases.
- IAM: `"Action": "*"` or `"Resource": "*"` on write actions, `iam:PassRole` to anyone, wildcard trust policies.
- Encryption and logging off: `encrypted = false`, no KMS on storage, CloudTrail or flow logs disabled.
- Secrets in `.tf` or `.tfvars` defaults (passwords, keys); state files committed to the repo.

## Dockerfiles
- No `USER` (runs as root), `--privileged` hints, `ADD <url>`, `curl … | sh`, unpinned `:latest` base images.
- Secrets in `ENV` or `ARG` (baked into image layers, readable with `docker history`).

## Kubernetes manifests
- `privileged: true`, `allowPrivilegeEscalation` not false, `hostNetwork`, `hostPID`, `hostPath` mounts,
  missing `runAsNonRoot`, added capabilities (`SYS_ADMIN`, `NET_ADMIN`).
- RBAC: `verbs: ["*"]` or `resources: ["*"]`, `cluster-admin` bound to a service account workloads use.
- Secrets as plain `env` values instead of `secretKeyRef`; `Service` of type `LoadBalancer` for an internal tool.

## GitHub Actions workflows
- Script injection: `${{ github.event.issue.title }}`, `…pull_request.title`, `…head_ref`, comment bodies used
  inside `run:`. Attacker-controlled text becomes shell (CWE-78). Safe: pass it through `env:` and quote it.
- `pull_request_target` or `workflow_run` that checks out and runs the pull request's code with secrets.
- Third-party actions pinned to a tag or branch instead of a commit SHA; `permissions: write-all` or none set
  on a workflow that only needs to read.
- Secrets echoed to logs or passed to steps that run untrusted code.

Severity: internet-reachable data exposure or code execution in CI with secrets is high or critical;
hardening gaps without a reachable attacker (missing `runAsNonRoot` on an internal job) are low.
