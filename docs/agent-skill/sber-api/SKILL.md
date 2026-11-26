---
name: sber-api
description: "Use when calling Sber Business API (СберБизнес API, fintech.sberbank.ru): tokens and mTLS files are provided by sber-cert-master."
version: 1.0.0
author: sber-cert-master
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [Finance, Bank, Sber, SberBusiness, API, mTLS]
---

# Sber Business API through sber-cert-master

Credentials are kept alive by the **sber-cert-master** service. It publishes everything you need into a
read-only directory `SBER_DIR` — `/var/lib/sber-cert-master/public/main` (the same path on a host and
inside agent containers, so the absolute paths in `env` are valid everywhere):

| File | Meaning |
|---|---|
| `token.json` | `access_token`, `expires_at` (unix time), `api_base` — **re-read before every request** |
| `tls/client.pem` | client private key + certificate (one file, for mTLS) |
| `ca-bundle.pem` | trusted CAs of the bank (Sber + Минцифры) |
| `env` | the same paths as shell variables |

## Rules (mandatory)

1. **Never** call `/ic/sso/api/v2/oauth/token`, `/ic/sso/api/v1/change-client-secret` or
   `/fintech/api/applications/secrets/v1/refresh-client-secret`. Refreshing tokens is the service's job;
   doing it yourself breaks access for everybody.
2. **Never** print, log or store the access token, and never put it on a command line
   (`curl -H "Authorization: …"` is visible in `ps`). Pass it via stdin as below.
3. Re-read `token.json` before each request — never keep the token in memory between requests. Every
   token refresh **immediately revokes the previous access token** (verified on production), and the
   service refreshes about every 40 minutes. On HTTP **401** re-read the file; if it holds the **same** token,
   wait (poll every few seconds, up to 30 s) until the service publishes a new one; then retry once. A
   single 401 right at a refresh is normal; if it is still 401, stop and report — do not try to obtain a
   token any other way.
4. Connect to the bank **directly**: if the environment has `HTTPS_PROXY`, make sure `.sberbank.ru` is in
   `NO_PROXY` (a generic proxy can make the mTLS handshake time out).
5. Anything that creates or signs documents (payments, `PAY_DOC_*`, letters, …) needs explicit
   confirmation from the human first. Reading (client info, statements, dictionaries) does not.
6. Retry automatically **only reads**. A write (creating a document) that ended in a timeout, 5xx, 408
   or 429 may already have been executed by the bank: do **not** resend it. Look the document up first
   (by its external id / number / list of documents); if you cannot verify the outcome, report to the
   human. One confirmation authorises one creation.
7. Never follow redirects with the token: a 3xx answer is an error to report, not a place to go.

## Making a request

```sh
SBER_DIR=${SBER_DIR:-/var/lib/sber-cert-master/public/main}
API=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["api_base"])' "$SBER_DIR/token.json")
sber_get() {   # usage: sber_get /fintech/api/v1/client-info
  python3 -c 'import json,sys; print("Authorization: Bearer " + json.load(open(sys.argv[1]))["access_token"])' \
      "$SBER_DIR/token.json" |
    NO_PROXY="$NO_PROXY,.sberbank.ru" no_proxy="$no_proxy,.sberbank.ru" \
    curl -q -sS --fail-with-body --max-redirs 0 -H @- -H 'Accept: application/json' \
      --cert "$SBER_DIR/tls/client.pem" --cacert "$SBER_DIR/ca-bundle.pem" "$API$1"
}
sber_get /fintech/api/v1/client-info
```

Python:

```python
import json, ssl, urllib.request
D = "/var/lib/sber-cert-master/public/main/"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never carry the token to another location

tok = json.load(open(D + "token.json"))
ctx = ssl.create_default_context(cafile=D + "ca-bundle.pem")
ctx.load_cert_chain(D + "tls/client.pem")
req = urllib.request.Request(tok["api_base"] + "/fintech/api/v1/client-info",
                             headers={"Authorization": "Bearer " + tok["access_token"], "Accept": "application/json"})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx),
                                     NoRedirect())
print(json.load(opener.open(req, timeout=60)))
```

Useful read-only endpoints: `GET /fintech/api/v1/client-info` (organisation, accounts),
`GET /fintech/api/v2/statement/summary?accountNumber=…&statementDate=YYYY-MM-DD`,
`GET /fintech/api/v2/statement/transactions?accountNumber=…&statementDate=YYYY-MM-DD&page=1`.
Full documentation: https://developers.sber.ru/docs/ru/sber-api/overview

## When something fails

1. Run `sber-cert-master diagnose main --publish-dir /var/lib/sber-cert-master/public` (works without
   access to the service config). It prints findings in order of severity, each with the evidence and
   what to do. Exit code: 0 ok, 1 warnings, 2 critical. It never prints secrets.
2. Do what the first 🔴 finding says. Steps marked [ЧЕЛОВЕК] need a human: ask, don't improvise.
3. `health.json` in the same directory shows what the service itself thinks (last refresh error, open
   alerts, recent events) — no secrets, readable by agents.
4. If the findings do not explain the failure or the fix did not help, file a bug report:
   `sber-cert-master diagnose main --publish-dir /var/lib/sber-cert-master/public --issue <owner>/<private-repo>`
   (needs an authenticated `gh`; otherwise save the report to a file and give it to the human).
   Describe in the issue what you were doing and what you already tried.

Full error catalog (bank codes observed on prod, service alerts, permissions): `docs/ERRORS.md` in the
sber-cert-master repository.

If `token.json` is missing, stale (`expires_at` in the past) or you get permission denied on these files,
the problem is in the sber-cert-master deployment — report it, do not work around it.
