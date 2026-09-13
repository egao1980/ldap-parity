# ldap-parity

Interop canary: **[`ldap-protocol`](https://github.com/egao1980/ldap-protocol)** vs dockerized **OpenLDAP**. Bind and search reuse the protocol request GFs; add uses the protocol BER writers (wire `ldap-add` is not in wave-1). Responses are decoded here.

Mock/in-memory coverage stays in `ldap-protocol`. This repo is **live interop** only.

## Run

Default `asdf:test-system` is green **without Docker** — live cases `skip` when slapd is unreachable.

```bash
ros -e '(asdf:test-system "ldap-parity")' -q
```

Live:

```bash
docker compose up --wait
ros -e '(asdf:test-system "ldap-parity")' -q
```

```bash
PARITY=0 ros -e '(asdf:test-system "ldap-parity")' -q
```

Compose uses **`vegardit/openldap:2.6.10`** with env-only seed (`LDAP_INIT_ORG_DN=dc=example,dc=com`). osixia 1.5.0 stayed unhealthy in CI (missing base / invalid admin DN). The live canary binds as admin and adds its own `cn=canary-*` entry.

## Optional AD-schema fixture

`fixtures/ad-lite.schema` + `fixtures/ad-lite.ldif` add `sAMAccountName` / `userPrincipalName`. They are **not** mounted by default. The AD Rove case **skips** when that attribute is absent. The bind/search/add canary writes `cn=canary-*` under `dc=example,dc=com` (override with `LDAP_PARITY_PEOPLE`).

## Env

| Variable | Default | Meaning |
|----------|---------|---------|
| `PARITY` | probe | `0`/`false`/`off` skips live cases |
| `LDAP_PARITY` | probe | same, LDAP-only |
| `LDAP_PARITY_HOST` | `127.0.0.1` | slapd host |
| `LDAP_PARITY_PORT` | `389` | LDAP port |
| `LDAP_PARITY_BIND_DN` | `cn=admin,dc=example,dc=com` | simple bind |
| `LDAP_PARITY_PASSWORD` | `admin` | bind password |
| `LDAP_PARITY_BASE` | `dc=example,dc=com` | search base |
| `LDAP_PARITY_AD` | unset | require AD-lite entries |

## Compose pins

| Service | Image |
|---------|--------|
| OpenLDAP | `vegardit/openldap:2.6.10` |

## License

MIT
