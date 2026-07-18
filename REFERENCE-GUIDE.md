# Ultimate Bug Bounty Wordlist — Reference Guide

**Total Entries:** 50,477 unique paths (100,954 with/without leading slash variants)
**Format:** One path per line, no leading slash — drop-in ready for ffuf, gobuster, feroxbuster, dirsearch
**Generated:** July 2026

---

## Quick Start — ffuf Commands

```bash
# Basic directory/file fuzzing
ffuf -u https://target.com/FUZZ -w ultimate-bugbounty-ffuf.txt -mc 200,204,301,302,307,401,403,405,500 -t 100

# With rate limiting (recommended for bug bounty)
ffuf -u https://target.com/FUZZ -w ultimate-bugbounty-ffuf.txt -mc 200,204,301,302,307,401,403,405,500 -rate 100

# Filter by response size (remove false positives)
ffuf -u https://target.com/FUZZ -w ultimate-bugbounty-ffuf.txt -mc all -fs 0 -fw 1

# Recursive fuzzing (2 levels deep)
ffuf -u https://target.com/FUZZ -w ultimate-bugbounty-ffuf.txt -mc 200,301,302,403 -recursion -recursion-depth 2

# With custom headers (bypass WAF/auth)
ffuf -u https://target.com/FUZZ -w ultimate-bugbounty-ffuf.txt -H "X-Forwarded-For: 127.0.0.1" -H "X-Original-URL: /FUZZ"

# POST request fuzzing
ffuf -u https://target.com/FUZZ -w ultimate-bugbounty-ffuf.txt -X POST -mc 200,204,301,302,405

# Subdirectory fuzzing (after finding /api/)
ffuf -u https://target.com/api/FUZZ -w ultimate-bugbounty-ffuf.txt -mc 200,204,301,302,401,403,405,500

# Virtual host discovery
ffuf -u https://target.com -w ultimate-bugbounty-ffuf.txt -H "Host: FUZZ.target.com" -fs 0
```

---

## Categories Covered

### 1. Version Control & Source Code Exposure
**Why it matters:** Exposed `.git` directories = full source code reconstruction with `git-dumper`. Instant critical finding on most programs.

**Key paths:** `.git/config`, `.git/HEAD`, `.git/index`, `.git/logs/HEAD`, `.git/packed-refs`, `.svn/entries`, `.svn/wc.db`, `.hg/hgrc`, `.gitignore`, `.gitmodules`

**What to do when found:**
- Use `git-dumper` to reconstruct the repo
- Search for hardcoded secrets, API keys, database credentials
- Map internal architecture and find hidden endpoints

---

### 2. Environment & Configuration Files
**Why it matters:** `.env` files frequently contain database passwords, API keys, SMTP credentials, and third-party service tokens.

**Key paths:** `.env`, `.env.local`, `.env.production`, `.env.backup`, `.env.bak`, `.env.old`, `.env.swp`, `config.env`, `app.env`

**Severity:** Critical — direct credential exposure

---

### 3. Cloud Provider Configurations
**Why it matters:** Exposed cloud credentials = full account takeover. AWS credentials alone caused 23% of cloud security incidents in 2025.

**Key paths:**
- **AWS:** `.aws/credentials`, `.aws/config`, `aws-exports.js`
- **GCP:** `service-account.json`, `google-credentials.json`, `application_default_credentials.json`
- **Azure:** `.azure/accessTokens.json`, `azure-credentials.json`
- **Firebase:** `firebase.json`, `.firebaserc`, `database.rules.json`, `__/firebase/init.json`
- **Terraform:** `terraform.tfstate`, `terraform.tfvars` (state files contain all secrets in plaintext)
- **Supabase:** `supabase/config.toml`, `supabase/.env`
- **Vercel/Netlify:** `vercel.json`, `netlify.toml`, `.vercel/project.json`

---

### 4. CI/CD Pipeline Configs
**Why it matters:** 59% of credential compromises in 2025 came from CI/CD runners. Pipeline configs often contain encrypted secrets that can be decrypted.

**Key paths:** `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, `.travis.yml`, `.drone.yml`, `bitbucket-pipelines.yml`, `buildspec.yml`, `.buildkite/pipeline.yml`

---

### 5. Docker & Kubernetes
**Why it matters:** Exposed kubeconfig = cluster admin access. Docker compose files leak database passwords and internal service topology.

**Key paths:** `Dockerfile`, `docker-compose.yml`, `.docker/config.json`, `.kube/config`, `kubeconfig.yaml`, `values.yaml`, `secrets.yaml`, `deployment.yaml`, `helmfile.yaml`

---

### 6. API Documentation & Endpoints
**Why it matters:** Exposed Swagger/OpenAPI docs reveal every endpoint, parameter, and data model. GraphQL introspection exposes the entire schema.

**Key paths:**
- **Swagger:** `swagger.json`, `swagger-ui.html`, `api-docs`, `swagger/v1/swagger.json`
- **OpenAPI:** `openapi.json`, `openapi.yaml`, `openapi/v3/api-docs`
- **GraphQL:** `graphql`, `graphiql`, `graphql/playground`, `altair`, `voyager`
- **gRPC:** `grpc/reflection`
- **Internal API:** `api/internal`, `api/private`, `api/debug`, `api/admin`

---

### 7. Admin Panels & Dashboards
**Why it matters:** Exposed admin panels with default credentials or no auth = game over.

**Key paths:**
- **Generic:** `admin`, `dashboard`, `console`, `panel`, `portal`, `manage`
- **CMS:** `wp-admin`, `administrator`, `cpanel`
- **Monitoring:** `grafana`, `kibana`, `prometheus`, `jaeger`, `sentry`
- **DevOps:** `jenkins`, `sonarqube`, `nexus`, `artifactory`, `vault/ui`, `consul/ui`
- **Data:** `phpmyadmin`, `adminer`, `mongo-express`, `redis`
- **Containers:** `portainer`, `rancher`, `traefik/dashboard`
- **ML/Data:** `airflow`, `mlflow`, `jupyter`, `superset`, `metabase`, `redash`

---

### 8. Spring Boot Actuator (Java)
**Why it matters:** Actuator endpoints expose environment variables (with secrets), heap dumps (memory with credentials), and can sometimes enable RCE via `shutdown` or `jolokia`.

**Key paths:** `actuator/env`, `actuator/heapdump`, `actuator/configprops`, `actuator/mappings`, `actuator/beans`, `actuator/threaddump`, `actuator/jolokia`, `actuator/gateway/routes`

**Severity:** Critical for `heapdump` (memory dump with secrets) and `env` (plaintext credentials)

---

### 9. Debug & Development Endpoints
**Why it matters:** Left-behind debug endpoints bypass authentication and expose internal state.

**Key paths:**
- **Django:** `__debug__`, `__debug__/sql`
- **Laravel:** `telescope`, `horizon`, `_debugbar/open`, `_ignition/health-check`
- **Rails:** `rails/info/properties`, `rails/info/routes`, `sidekiq`, `letter_opener`
- **Go:** `debug/pprof`, `debug/vars`, `pprof/heap`, `pprof/goroutine`
- **ASP.NET:** `elmah.axd`, `trace.axd`, `Telerik.Web.UI.DialogHandler.aspx`
- **Node:** `__webpack_hmr`, `socket.io`, `__coverage__`

---

### 10. Database Files & Exports
**Why it matters:** Exposed SQL dumps = complete database with user data, passwords, PII.

**Key paths:** `dump.sql`, `backup.sql`, `database.sql.gz`, `db.sqlite3`, `users.sql`, date-based patterns like `backup-2025-07.sql.gz`

**Coverage:** Includes date-based patterns for 2022-2026 with all common archive extensions.

---

### 11. Backup & Archive Files
**Why it matters:** Backup archives often contain full application source code, databases, and configuration with credentials.

**Key paths:** `backup.zip`, `site.tar.gz`, `www.zip`, `htdocs.tar.gz`, `public_html.zip`, plus extensive permutations of common names with backup/archive extensions.

---

### 12. Secrets, Keys & Credentials
**Why it matters:** Direct credential exposure. SSH keys = server access. SSL keys = traffic decryption.

**Key paths:** `.ssh/id_rsa`, `server.key`, `private.pem`, `keystore.jks`, `token.json`, `credentials.json`, `client_secret.json`, `master.key`, `.bash_history`, `.mysql_history`, `.pgpass`, `.netrc`

---

### 13. Log Files
**Why it matters:** Logs leak stack traces, internal IPs, user data, session tokens, and SQL queries.

**Key paths:** `access.log`, `error.log`, `debug.log`, `wp-content/debug.log`, `storage/logs/laravel.log`, `log/production.log`, `catalina.out`, `npm-debug.log`

---

### 14. CMS-Specific (WordPress, Joomla, Drupal, Magento)
**Why it matters:** CMS installations have well-known vulnerable paths. WordPress REST API at `wp-json/wp/v2/users` exposes usernames by default.

**Key paths:** `wp-config.php`, `wp-json/wp/v2/users`, `xmlrpc.php`, `wp-content/debug.log`, plugin `readme.txt` files for version detection, `configuration.php`, `sites/default/settings.php`, `app/etc/env.php`

**Coverage:** Includes 60+ popular WordPress plugin paths for version fingerprinting.

---

### 15. SSRF/LFI Target Paths
**Why it matters:** When you find an SSRF or LFI, these are the paths you want to read.

**Key paths:**
- **Cloud metadata:** `169.254.169.254/latest/meta-data/iam/security-credentials/`
- **System:** `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `/proc/self/cmdline`
- **Kubernetes:** `/var/run/secrets/kubernetes.io/serviceaccount/token`
- **Docker:** `/var/run/docker.sock`, `/.dockerenv`

---

### 16. OAuth & SSO Endpoints
**Why it matters:** Misconfigured OAuth flows enable account takeover via open redirects, token theft, or authorization code interception.

**Key paths:** `oauth/authorize`, `oauth/token`, `oauth/callback`, `saml/metadata`, `.well-known/openid-configuration`, `.well-known/jwks.json`, `connect/authorize`, `connect/token`, `simplesaml`

---

### 17. AI/ML & Modern Tech (2024-2026)
**Why it matters:** New attack surface. AI config files contain API keys. Exposed model files leak proprietary models.

**Key paths:** `.openai`, `openai.json`, `.anthropic`, `claude.json`, `.well-known/ai-plugin.json`, `model.safetensors`, `.cursor/settings.json`, `CLAUDE.md`, `.cursorrules`, `.aider.conf.yml`, `ollama.conf`, `langchain.yaml`, `deno.json`, `bunfig.toml`

---

### 18. Modern Framework Internals (Next.js, Nuxt, Remix, etc.)
**Why it matters:** Framework-specific paths expose build IDs, source maps, internal routes, and debug interfaces.

**Key paths:** `_next/data/BUILD_ID/index.json`, `_nuxt/manifest.js`, `_payload.json`, `__nextjs_original-stack-frame`, `@vite/client`, `__vite_ping`, `asset-manifest.json`, `storybook-static`

---

### 19. Elasticsearch & Search Engines
**Why it matters:** Exposed Elasticsearch clusters with no auth = read/modify/delete all data.

**Key paths:** `_cluster/health`, `_cat/indices`, `_all/_search`, `_mapping`, `_security/user`, `_security/role`, `_opendistro/_security/api/roles`

---

### 20. Well-Known URIs
**Why it matters:** Standard discovery paths defined by IANA. Many reveal security configurations, authentication endpoints, and trust relationships.

**Key paths:** `.well-known/security.txt`, `.well-known/openid-configuration`, `.well-known/jwks.json`, `.well-known/apple-app-site-association`, `.well-known/assetlinks.json`, `.well-known/ai-plugin.json`, `.well-known/terraform.json`, `.well-known/passkey-endpoints`

---

### 21. Directory Indexing Targets
**Why it matters:** Directories with trailing slashes are most likely to have open directory listing enabled, exposing all contained files.

**Key paths:** `uploads/`, `backups/`, `logs/`, `private/`, `secret/`, `exports/`, `certs/`, `keys/`, `.git/objects/`, `node_modules/`, `storage/logs/`

---

### 22. Webhook & Callback Endpoints
**Why it matters:** Webhook endpoints often lack proper authentication and can be abused for SSRF, data exfiltration, or business logic manipulation.

**Coverage:** 50+ services (Stripe, PayPal, GitHub, Slack, etc.) with `webhook/`, `callback/`, `hooks/`, `api/webhook/` prefixes.

---

### 23. IDE & Editor Artifacts
**Why it matters:** IDE config files leak server credentials (SFTP/FTP configs), database connection strings, and internal project structure.

**Key paths:** `.vscode/sftp.json`, `.vscode/ftp-sync.json`, `.idea/dataSources.xml`, `.idea/webServers.xml`, `sftp-config.json`, `.ftpconfig`, `.ftppass`, `.remote-sync.json`, `.DS_Store`

---

### 24. Hidden/Internal API Endpoints
**Why it matters:** Developers often create hidden endpoints prefixed with `__`, `_`, or nested under `/internal/` that bypass authentication.

**Key paths:** `api/__internal__`, `api/__debug__`, `api/_admin`, `internal/api`, `private/graphql`, `hidden/admin`, `__api__`, `api/beta`, `api/experimental`, `api/edge`

---

## Pro Tips

1. **Start with rate limiting** — `ffuf -rate 100` to avoid getting banned
2. **Filter aggressively** — Use `-fs` (filter size), `-fw` (filter words), `-fl` (filter lines) to remove false positives
3. **Chain findings** — Found `/api/`? Run the wordlist again against `https://target.com/api/FUZZ`
4. **Check response codes** — 403 is valuable (path exists but forbidden — try bypass techniques)
5. **Use multiple wordlists** — Run this first, then target-specific wordlists for technologies you've identified
6. **Match on 401/403** — These confirm path existence even without access
7. **Source maps** — Finding `.js.map` files lets you reconstruct the original source code
8. **Actuator heapdump** — Download and search with `strings heapdump | grep password` for instant wins

---

## What Makes This Wordlist Different

- **2024-2026 technology coverage:** AI/ML configs, Cursor/Claude/Copilot files, Bun/Deno, tRPC, Prisma, PocketBase, n8n, Temporal, OpenTelemetry
- **Deep API enumeration:** 3-level versioned REST paths with actions, query parameter fuzzing, ID enumeration
- **Date-based backups:** Full coverage of `backup-YYYY-MM.ext` patterns for 2022-2026
- **Cloud-native:** Kubernetes secrets, Terraform state, Helm values, Docker configs, cloud metadata SSRF paths
- **60+ WordPress plugins:** Version fingerprinting via readme.txt paths
- **50+ webhook services:** Stripe, GitHub, Slack, and more with multiple prefix patterns
- **Elasticsearch deep:** 40+ cluster/node/index/security endpoints
- **No junk entries:** Every path has a documented security rationale

---

## Sources & Research

- [SecLists by Daniel Miessler](https://github.com/danielmiessler/SecLists)
- [Karanxa/Bug-Bounty-Wordlists](https://github.com/Karanxa/Bug-Bounty-Wordlists)
- [GitGuardian State of Secrets Sprawl 2026](https://passwork.pro/blog/the-state-of-secrets-sprawl-in-2026/)
- [Cloud Misconfiguration Guide](https://github.com/nukIeer/Cloud-Misconfig-Exploit-Guide)
- [Supabase Misconfiguration Research](https://deepstrike.io/blog/hacking-thousands-of-misconfigured-supabase-instances-at-scale)
- [Intigriti Custom Wordlists Guide](https://www.intigriti.com/researchers/blog/hacking-tools/creating-custom-wordlists-for-bug-bounty-targets-a-complete-guide)
- [InfoSec Write-ups Sensitive Endpoints](https://infosecwriteups.com/sensitive-endpoint-wordlist-for-bug-hunting-1acb50034629)
