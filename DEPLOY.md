# Deploy a producción — runtime-supervisor

Tiempo: ~30 minutos. Resultado: supervisor corriendo en
`https://api.tudominio.com` + consola en `https://app.tudominio.com`.

## Pre-requisitos

- Una VPS (tested en Hetzner CX11 €4/mes, Digital Ocean $6 droplet, AWS t3.micro).
  - Mínimo: 2 GB RAM, 1 vCPU, 20 GB disco.
  - Docker 24+ instalado (`curl -fsSL https://get.docker.com | sh`).
- Un dominio donde puedas editar registros A.
- Acceso SSH a la VPS.

---

## Paso 1 — Registros DNS

En el panel de tu registrar, apuntá 2 subdomains a la IP de la VPS:

```
api.tudominio.com  A  <IP_VPS>
app.tudominio.com  A  <IP_VPS>
```

Esperá que propaguen (puede tardar minutos a horas). Verificá con:

```
dig +short api.tudominio.com
dig +short app.tudominio.com
```

Las dos tienen que devolver la IP del VPS.

## Paso 2 — Clonar el repo y configurar env

En la VPS:

```
git clone https://github.com/ArielSanroj/runtime-supervisor.git
cd runtime-supervisor
cp .env.prod.example .env.prod
```

Editá `.env.prod`:

- `API_DOMAIN` y `APP_DOMAIN` → tus 2 subdomains del paso 1.
- `EVIDENCE_HMAC_SECRET`, `WEBHOOK_SECRET`, `POSTGRES_PASSWORD`, `ADMIN_BOOTSTRAP_TOKEN` → generá con `openssl rand -hex 32` (o `-hex 24` para el admin token).
- `UI_SUPERVISOR_APP_ID` y `UI_SUPERVISOR_SECRET` → dejalos vacíos por ahora. Se llenan en el paso 5.

## Paso 3 — Arrancar el stack

```
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d
```

Observá los logs los primeros 2 minutos:

```
docker compose --env-file .env.prod -f docker-compose.prod.yml logs -f
```

Deberías ver en orden:
1. `postgres`: "database system is ready to accept connections"
2. `supervisor`: "INFO  [alembic.runtime.migration] Running upgrade ... -> 0010"
3. `supervisor`: "Uvicorn running on http://0.0.0.0:8000"
4. `caddy`: "certificate obtained successfully"
5. `control-center`: "Ready on port 3000"

Verificá que responde:

```
curl https://api.tudominio.com/v1/action-types
# → debería devolver {"action_types":[...]}
```

## Paso 4 — Crear el primer admin + la integration del UI

El admin bootstrap token que seteaste en `.env.prod` es la llave para crear
el primer usuario humano (para loggearse a la UI) y la primera integration
(para que el UI hable con el supervisor).

**Crear el user admin:**

```
curl -X POST https://api.tudominio.com/v1/users \
  -H "X-Admin-Token: $(grep ADMIN_BOOTSTRAP_TOKEN .env.prod | cut -d= -f2)" \
  -H "content-type: application/json" \
  -d '{"email":"tu@email.com","password":"tu-password-seguro","role":"admin"}'
```

**Crear la integration del UI:**

```
curl -X POST https://api.tudominio.com/v1/integrations \
  -H "X-Admin-Token: $(grep ADMIN_BOOTSTRAP_TOKEN .env.prod | cut -d= -f2)" \
  -H "content-type: application/json" \
  -d '{"name":"ui-server","scopes":["*"]}'
```

La respuesta trae `id` + `shared_secret`. Copiálos a `.env.prod`:

```
UI_SUPERVISOR_APP_ID=<el id>
UI_SUPERVISOR_SECRET=<el shared_secret>
```

## Paso 5 — Redeploy del control-center con las creds

```
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d --no-deps control-center
```

Abrí `https://app.tudominio.com` → entrás al login. Usá las credenciales que creaste en el paso 4.

---

## Policies iniciales

El supervisor arranca con las 6 policies shipeadas en `packages/policies/` como fallback en disco. Para poder editarlas desde la UI, promové cada una:

```
for pol in refund payment tool_use account_change data_access compliance; do
  POLICY=$(cat packages/policies/${pol}.base.v1.yaml | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
  curl -s -X POST https://api.tudominio.com/v1/policies \
    -H "X-Admin-Token: $(grep ADMIN_BOOTSTRAP_TOKEN .env.prod | cut -d= -f2)" \
    -H "content-type: application/json" \
    -d "{\"action_type\":\"${pol}\",\"yaml_source\":${POLICY},\"promote\":true}"
  echo ""
done
```

---

## Conectar un repo cliente

Desde el cliente (Clio, supervincent, etc) que ya tenga
`@supervised` + `configure_supervisor()` cableados:

```
# .env del cliente
SUPERVISOR_BASE_URL=https://api.tudominio.com
SUPERVISOR_APP_ID=<id de una integration creada para ese cliente>
SUPERVISOR_SECRET=<shared_secret>
SUPERVISOR_ENFORCEMENT_MODE=shadow   # ver ROLLOUT.md
```

Crear la integration del cliente (en el servidor):

```
curl -X POST https://api.tudominio.com/v1/integrations \
  -H "X-Admin-Token: ..." \
  -H "content-type: application/json" \
  -d '{"name":"clio-prod","scopes":["payment","tool_use","refund"]}'
```

Redeploy del cliente con esas vars → `docker compose logs` del supervisor
debería empezar a mostrar requests de evaluate entrantes.

---

## Backup del evidence log

Crítico para compliance — el hash chain es tu prueba de integridad. Backup
diario del volumen postgres:

```
# en la VPS, crontab -e
0 3 * * * docker compose --env-file ~/runtime-supervisor/.env.prod -f ~/runtime-supervisor/docker-compose.prod.yml exec -T postgres pg_dump -U supervisor supervisor | gzip > /backups/supervisor-$(date +\%Y\%m\%d).sql.gz
```

Y/o export periódico de bundles firmados a S3:

```
# diario, itera sobre acciones sin export
curl -s https://api.tudominio.com/v1/actions/recent?limit=50 \
  -H "authorization: Bearer $(tu-jwt)" | \
  python3 -c 'import json,sys,subprocess; [subprocess.run(["curl","-sXPOST",f"https://api.tudominio.com/v1/decisions/{r[\"action_id\"]}/evidence/export","-H",f"authorization: Bearer {sys.argv[1]}"]) for r in json.load(sys.stdin)]' "$JWT"
```

---

## Rollback

Si algo sale mal:

```
docker compose --env-file .env.prod -f docker-compose.prod.yml down
```

La DB persiste en el volumen `supervisor_data`. Para wipe total:

```
docker compose --env-file .env.prod -f docker-compose.prod.yml down -v
```

⚠️ Eso **borra el evidence log completo**. Nunca hagas eso en prod sin haber exportado bundles antes.

---

## Monitoreo mínimo

```
# Health check simple
curl -f https://api.tudominio.com/v1/action-types || echo "supervisor down"

# Métricas de las últimas 24h
curl -H "authorization: Bearer $JWT" https://api.tudominio.com/v1/metrics/enforcement?window=24h
```

Conectá eso a Uptime Kuma / Better Uptime / lo que uses. Un page por
`api.tudominio.com` + alert si `total_evaluations` cae a 0 cuando debería
haber tráfico.

---

## Costos estimados

| Recurso | Provider | Costo |
|---|---|---|
| VPS 2GB | Hetzner CX11 | €4/mes |
| VPS 2GB | DigitalOcean | $6/mes |
| VPS t3.micro | AWS | $8/mes |
| Dominio | cualquier registrar | ~$15/año |
| TLS | Let's Encrypt vía Caddy | gratis |
| Backup S3 | AWS/Wasabi | <$1/mes para <10GB |

Total: **~$5-10/mes + dominio anual**.

---

## Upgrade path

Cuando este deploy se quede chico:

- **Separar DB**: mover postgres a un managed service (RDS, Supabase). Cambiar `DATABASE_URL` en `.env.prod`. El volumen local queda vacío.
- **Horizontal scale**: múltiples réplicas del supervisor detrás de caddy. Requiere leader election para el retry_worker — está en el ROADMAP.md.
- **SSO/OIDC**: reemplazar el login email+password por Clerk/Auth0. Es 1 archivo de middleware más un route `/api/auth/callback`.
