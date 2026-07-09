#!/bin/sh
# =====================================================================
# hardening/vault_commands.sh
# Example HashiCorp Vault CLI commands for storing and retrieving
# honeypot secrets (DB password, API keys, dashboard credentials).
#
# This is a REFERENCE script, not meant to be run end-to-end blindly —
# every `vault kv put` line below uses a placeholder value. Replace
# placeholders, and run the commands you need against a real Vault
# server you control. No Vault server exists in this build environment,
# so these commands are documented/syntax-reviewed, not executed.
# =====================================================================
set -eu

VAULT_ADDR="${VAULT_ADDR:-https://vault.internal.example.com:8200}"
export VAULT_ADDR

echo "# ── 1. Authenticate (example: AppRole, preferred for automation
#       over a static root/admin token) ──────────────────────────────"
cat << 'EOF'
vault write auth/approle/login \
    role_id="$VAULT_ROLE_ID" \
    secret_id="$VAULT_SECRET_ID"
# → returns a short-lived client token; export it as VAULT_TOKEN for
#   the subsequent commands, or use `vault login` interactively for
#   one-off manual operations.
EOF

echo ""
echo "# ── 2. Enable the KV v2 secrets engine (one-time, per Vault) ──"
cat << 'EOF'
vault secrets enable -path=secret kv-v2
EOF

echo ""
echo "# ── 3. Store the database credential ───────────────────────────"
cat << 'EOF'
vault kv put secret/honeypot/db \
    database_url="postgresql://honeypot_app:REPLACE_ME_REAL_PASSWORD@postgres.internal:5432/honeypot"
EOF

echo ""
echo "# ── 4. Store threat-intel API keys ─────────────────────────────"
cat << 'EOF'
vault kv put secret/honeypot/threat-intel \
    abuseipdb_api_key="REPLACE_ME" \
    virustotal_api_key="REPLACE_ME" \
    otx_api_key="REPLACE_ME" \
    shodan_api_key="REPLACE_ME" \
    cuckoo_api_token="REPLACE_ME"
EOF

echo ""
echo "# ── 5. Store dashboard auth secret + password hash ─────────────"
cat << 'EOF'
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
PASSWORD_HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('REPLACE_ME_REAL_PASSWORD'))")

vault kv put secret/honeypot/dashboard \
    secret_key="$SECRET_KEY" \
    password_hash="$PASSWORD_HASH"
EOF

echo ""
echo "# ── 6. Read a secret back (used by deploy scripts / Vault Agent
#       templates, NOT pasted into shell history in production) ────"
cat << 'EOF'
vault kv get -field=database_url secret/honeypot/db
EOF

echo ""
echo "# ── 7. Create a least-privilege policy scoping what the honeypot
#       app's AppRole can actually read (read-only, these 3 paths only) ──"
cat << 'EOF'
vault policy write honeypot-app-read - << 'POLICY'
path "secret/data/honeypot/db" {
  capabilities = ["read"]
}
path "secret/data/honeypot/threat-intel" {
  capabilities = ["read"]
}
path "secret/data/honeypot/dashboard" {
  capabilities = ["read"]
}
POLICY

vault write auth/approle/role/honeypot-app \
    token_policies="honeypot-app-read" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h
EOF

echo ""
echo "# ── 8. Render secrets into the systemd EnvironmentFile via Vault
#       Agent template (preferred over manual 'kv get' + paste) ───"
cat << 'EOF'
# /etc/vault-agent/honeypot-dashboard.ctmpl
HONEYPOT__DASHBOARD__SECRET_KEY={{ with secret "secret/data/honeypot/dashboard" }}{{ .Data.data.secret_key }}{{ end }}
HONEYPOT__DASHBOARD__PASSWORD_HASH={{ with secret "secret/data/honeypot/dashboard" }}{{ .Data.data.password_hash }}{{ end }}
HONEYPOT__THREAT_INTEL__ABUSEIPDB__API_KEY={{ with secret "secret/data/honeypot/threat-intel" }}{{ .Data.data.abuseipdb_api_key }}{{ end }}
HONEYPOT__THREAT_INTEL__VIRUSTOTAL__API_KEY={{ with secret "secret/data/honeypot/threat-intel" }}{{ .Data.data.virustotal_api_key }}{{ end }}

# vault-agent.hcl excerpt:
#   template {
#     source      = "/etc/vault-agent/honeypot-dashboard.ctmpl"
#     destination = "/etc/honeypot-suite/dashboard.env"
#     perms       = "0640"
#     command     = "systemctl restart honeypot-dashboard.service"
#   }
EOF

echo ""
echo "# ── 9. Rotate the DB password and update Vault in one step
#       (pair with a Postgres ALTER ROLE, not shown — DB-specific) ──"
cat << 'EOF'
NEW_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
vault kv put secret/honeypot/db \
    database_url="postgresql://honeypot_app:${NEW_PASSWORD}@postgres.internal:5432/honeypot"
# Then: ALTER ROLE honeypot_app WITH PASSWORD '$NEW_PASSWORD'; (run against Postgres)
# Then: restart consumers (systemctl restart honeypot-dashboard.service, or
#       kubectl rollout restart deployment/honeypot-ssh -n honeypot) to
#       pick up the new value via Vault Agent template / K8s Secret sync.
EOF
