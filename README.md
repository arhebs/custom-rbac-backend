# Custom RBAC Backend (Django/DRF)

A reference backend demonstrating custom authentication (JWT access + refresh) and database-backed RBAC with Redis
blocklisting and soft-delete behavior.

## Stack

- Python 3.10+, Django 4.x, DRF
- PostgreSQL for persistence
- Redis for JWT blocklist
- drf-spectacular for OpenAPI docs

## Quick Start

### With Docker Compose v2 (recommended)

1) Build & start: `docker compose up --build`
2) Run migrations inside app container: `docker compose exec app python src/manage.py migrate`
3) Seed RBAC data: `docker compose exec app python src/manage.py seed_rbac`
4) Open API docs at `http://localhost:8000/schema/swagger-ui/`

### Local env (no Docker)

1) Install deps: `pip install -r requirements.txt`
2) Apply migrations: `python src/manage.py migrate`
3) Seed baseline roles/rules/users/articles: `python src/manage.py seed_rbac`
4) Run server: `python src/manage.py runserver`

## OpenAPI Docs

- Raw schema: `/schema/`
- Swagger UI: `/schema/swagger-ui/`

## Data Model (simplified)

- `Role(id, name, description)`
- `User(id, email, password_hash, first_name, last_name, patronymic, role_id, is_active)`
- `BusinessElement(id, key)` — identifiers like `article`, `access_rule`, `user`
- `AccessRule(id, role_id, element_id, can_read_own/all, can_create, can_update_own/all, can_delete_own/all)` (unique
  per role+element)
- `Article(id, title, content, owner_id)`

## JWT Payload

```
{
  "sub": <user_id>,
  "jti": <unique_token_id>,
  "exp": <unix expiry>,
  "iat": <unix issued_at>,
  "role": <role name>,
  "type": "access" | "refresh"
}
```

- Access tokens expire ~15 minutes; refresh tokens are longer (~24h).
- `type` must match endpoint expectations (`access` for protected routes, `refresh` for /auth/refresh).

## Auth & Token Lifecycle

- Login issues access + refresh tokens.
- Middleware decodes access tokens, checks Redis blocklist, and ensures user is active.
- Logout blocklists the current access token only (refresh relies on signature/exp/type and active user).
- Soft delete (`DELETE /auth/me/`) sets `is_active=False` and blocklists the current access token. Inactive users cannot
  log in or refresh.

## Response Envelope

All non-204 responses use:

```
{
  "data": <payload or null>,
  "errors": [<messages>]  # empty list on success
}
```

## Status Code Semantics

- **401 Unauthorized**: missing/invalid/expired token, wrong token type, blocklisted token, user not found/inactive.
- **403 Forbidden**: authenticated but RBAC rule missing or denies action.
- **503 Service Unavailable**: Redis blocklist unavailable (fail-closed).

## RBAC Algorithm (summary)

1. Each view declares `business_element` (e.g., `article`, `access_rule`).
2. Retrieve `AccessRule` for `(user.role, business_element)`; if missing → 403.
3. Map HTTP method to required flags (read/create/update/delete; own vs all).
4. Object checks: allow if `*_all`; allow if `*_own` and `obj.owner == user`; else 403.
5. List scoping in `ArticleViewSet`: users with only `can_read_own` see their articles only.

## Seeding Defaults (`seed_rbac`)

Creates roles (Admin, User, Guest), business elements (`article`, `access_rule`, `user`), access rules (admin full; user
owns articles; guest read-only as configured), sample users, and sample articles.

## Testing

Run: `python src/manage.py test`
Covers auth flows (register/login/refresh/logout/soft delete) and RBAC matrices for articles and access-rule admin
endpoints.
