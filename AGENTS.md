# Instructions for AI agents

- **Installing / deploying this service:** follow [docs/AGENT_INSTALL.md](docs/AGENT_INSTALL.md) step by step (Docker: [deploy/docker/](deploy/docker/)).
- **Something fails (401, 403, timeout, Permission denied, an alert):** run `sber-cert-master diagnose main` (as an agent add `--publish-dir /var/lib/sber-cert-master/public`) and follow its findings; details in [docs/ERRORS.md](docs/ERRORS.md). If unexplained, file a bug report with `diagnose ... --issue <owner>/<private-repo>` — the command refuses non-private repositories. Reports contain no secrets but do contain client_id, INN and host name: never post them publicly.
- **Agent skill** (Hermes and similar): [docs/agent-skill/sber-api/SKILL.md](docs/agent-skill/sber-api/SKILL.md).
- **Using it from another agent:** read the token from `<publish_dir>/<profile>/token.json` (or `sber-cert-master token <profile>`) before each request; for mTLS use `tls/client.pem` (key+cert) and `ca-bundle.pem` from the same directory, or the paths in `env`. Never call `/oauth/token`, `/change-client-secret` or `/refresh-client-secret` yourself, and never put a token on a command line (use `curl -H @-`); on 401 re-read the file and retry once.
- **Never** print, log, commit or pass on the command line: client_secret, refresh/access tokens, .p12 password, private keys.
- **Developing:** stdlib-only Python ≥ 3.11 plus the `openssl` CLI. Run `python3 -m unittest discover -s tests` (fake bank with mTLS) before committing. Temp files go to `$TMPDIR` or `~/.cache/agent-tmp`, never `/tmp`.
