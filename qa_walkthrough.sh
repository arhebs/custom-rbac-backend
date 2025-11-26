#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Manual QA Walkthrough Script for Custom RBAC Backend
#
# - Starts Docker stack (db, redis, app)
# - Waits for the API to be available
# - Runs migrations + seed_rbac
# - Exercises main auth & RBAC flows against the live API
#
# Requirements:
#   - docker (with `docker compose` or `docker-compose`)
#   - curl
#   - jq
#
# Usage:
#   chmod +x qa_walkthrough.sh
#   ./qa_walkthrough.sh
#
# Optional env vars:
#   BASE_URL (default: http://localhost:8000)
###############################################################################

BASE_URL="${BASE_URL:-http://localhost:8000}"

if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 1
fi

# Detect docker compose
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "ERROR: docker compose or docker-compose is required" >&2
  exit 1
fi

echo "=== QA Walkthrough starting against ${BASE_URL} ==="

###############################################################################
# Helper functions
###############################################################################

LAST_BODY=""

api_call() {
  local label="$1"
  local method="$2"
  local path="$3"
  local expected_status="$4"
  local data="${5:-}"
  local token="${6:-}"

  local url="${BASE_URL}${path}"

  echo
  echo "----- ${label} -----"
  echo "${method} ${url}"

  local resp
  local headers=(-H "Content-Type: application/json")
  if [[ -n "${token}" ]]; then
    headers+=(-H "Authorization: Bearer ${token}")
  fi

  if [[ -n "${data}" ]]; then
    resp=$(curl -s -w '\n%{http_code}' -X "${method}" "${url}" "${headers[@]}" -d "${data}")
  else
    resp=$(curl -s -w '\n%{http_code}' -X "${method}" "${url}" "${headers[@]}")
  fi

  local body status
  body="$(printf '%s\n' "${resp}" | sed '$d')"
  status="$(printf '%s\n' "${resp}" | tail -n1)"

  echo "HTTP ${status}"
  if [[ -n "${body}" ]]; then
    if echo "${body}" | jq . >/dev/null 2>&1; then
      echo "${body}" | jq .
    else
      echo "${body}"
    fi
  fi

  if [[ "${status}" != "${expected_status}" ]]; then
    echo "!! EXPECTED HTTP ${expected_status} but got ${status} for: ${label}" >&2
    exit 1
  fi

  LAST_BODY="${body}"
}

wait_for_app() {
  echo
  echo "Waiting for API at ${BASE_URL} to become available..."
  local max_attempts=30
  local attempt=1

  while (( attempt <= max_attempts )); do
    if curl -s "${BASE_URL}/schema/" >/dev/null 2>&1; then
      echo "API is up (responded on /schema/)"
      return 0
    fi
    echo "  Attempt ${attempt}/${max_attempts} ... not ready yet"
    attempt=$((attempt + 1))
    sleep 2
  done

  echo "ERROR: API did not become ready in time" >&2
  exit 1
}

###############################################################################
# 1. Start Docker stack and prepare DB
###############################################################################

echo
echo "=== 1) Starting Docker stack ==="
${COMPOSE} up -d --build

wait_for_app

echo
echo "=== 2) Running migrations & seed_rbac ==="
${COMPOSE} exec app python src/manage.py migrate
${COMPOSE} exec app python src/manage.py seed_rbac

###############################################################################
# 2. Basic auth flows: admin & user
###############################################################################

echo
echo "=== 3) Auth: admin and user logins ==="

# Admin login (seeded by seed_rbac)
api_call \
  "Admin login" \
  "POST" "/auth/login/" "200" \
  '{"email":"admin@example.com","password":"adminpass"}'

ADMIN_ACCESS=$(echo "${LAST_BODY}" | jq -r '.data.access')
ADMIN_REFRESH=$(echo "${LAST_BODY}" | jq -r '.data.refresh')

# User login (seeded by seed_rbac)
api_call \
  "Standard user login" \
  "POST" "/auth/login/" "200" \
  '{"email":"user@example.com","password":"userpass"}'

USER_ACCESS=$(echo "${LAST_BODY}" | jq -r '.data.access')
USER_REFRESH=$(echo "${LAST_BODY}" | jq -r '.data.refresh')

###############################################################################
# 3. RBAC on Articles: admin vs user
###############################################################################

echo
echo "=== 4) RBAC on /articles/ ==="

# 4.1 Admin should see all seeded articles
api_call \
  "Admin: list all articles" \
  "GET" "/articles/" "200" "" "${ADMIN_ACCESS}"

ADMIN_ARTICLE_COUNT=$(echo "${LAST_BODY}" | jq '.data | length')
echo "Admin sees ${ADMIN_ARTICLE_COUNT} articles (expected >= 4)"

# 4.2 User should see only own articles (2 from seeder)
api_call \
  "User: list own articles" \
  "GET" "/articles/" "200" "" "${USER_ACCESS}"

USER_ARTICLE_COUNT=$(echo "${LAST_BODY}" | jq '.data | length')
echo "User sees ${USER_ARTICLE_COUNT} articles (expected 2)"

# 4.3 User creates a new article
api_call \
  "User: create own article" \
  "POST" "/articles/" "201" \
  '{"title":"QA User Article","content":"Created by QA script."}' \
  "${USER_ACCESS}"

USER_ARTICLE_ID=$(echo "${LAST_BODY}" | jq -r '.data.id')
echo "User-created article id: ${USER_ARTICLE_ID}"

# 4.4 User updates their own article
api_call \
  "User: update own article" \
  "PATCH" "/articles/${USER_ARTICLE_ID}/" "200" \
  '{"title":"QA User Article (updated)"}' \
  "${USER_ACCESS}"

# 4.5 Guest behavior simulated via Guest login
api_call \
  "Guest login" \
  "POST" "/auth/login/" "200" \
  '{"email":"guest@example.com","password":"guestpass"}'

GUEST_ACCESS=$(echo "${LAST_BODY}" | jq -r '.data.access')

api_call \
  "Guest: list articles (read-only)" \
  "GET" "/articles/" "200" "" "${GUEST_ACCESS}"

api_call \
  "Guest: attempt to create article (should be forbidden)" \
  "POST" "/articles/" "403" \
  '{"title":"Guest Not Allowed","content":"Should fail."}' \
  "${GUEST_ACCESS}"

###############################################################################
# 4. 401 vs 403 semantics
###############################################################################

echo
echo "=== 5) 401 vs 403 semantics ==="

# 5.1 Missing Authorization header on protected endpoint → 401
api_call \
  "No auth: GET /articles/ should be 401" \
  "GET" "/articles/" "401"

# 5.2 Authenticated user with no AccessRule for access_rule → 403
api_call \
  "User: attempt to list access rules (should be 403)" \
  "GET" "/access-rules/" "403" "" "${USER_ACCESS}"

###############################################################################
# 5. Access-rule admin API (Admin only)
###############################################################################

echo
echo "=== 6) AccessRule admin API as Admin ==="

# 6.1 Admin can list access rules
api_call \
  "Admin: list access rules" \
  "GET" "/access-rules/" "200" "" "${ADMIN_ACCESS}"

ACCESS_RULE_COUNT=$(echo "${LAST_BODY}" | jq '.data | length')
echo "Admin sees ${ACCESS_RULE_COUNT} access rules"

# 6.2 Creating duplicate (User, article) AccessRule should yield 400
DUP_RULE_PAYLOAD='{
  "role": "User",
  "element": "article",
  "can_read_own": true,
  "can_read_all": false,
  "can_create": true,
  "can_update_own": true,
  "can_update_all": false,
  "can_delete_own": true,
  "can_delete_all": false
}'

api_call \
  "Admin: create duplicate AccessRule (expect 400)" \
  "POST" "/access-rules/" "400" \
  "${DUP_RULE_PAYLOAD}" \
  "${ADMIN_ACCESS}"

###############################################################################
# 6. Token lifecycle: refresh, logout, soft delete
###############################################################################

echo
echo "=== 7) Token lifecycle: refresh, logout, soft delete ==="

# 7.1 Refresh token for user
api_call \
  "User: refresh token" \
  "POST" "/auth/refresh/" "200" \
  "{\"refresh\":\"${USER_REFRESH}\"}"

NEW_USER_ACCESS=$(echo "${LAST_BODY}" | jq -r '.data.access')

# 7.2 Logout should blocklist token
api_call \
  "User: logout (blocklist access token)" \
  "POST" "/auth/logout/" "204" "" "${NEW_USER_ACCESS}"

# Using the same token on /auth/me/ should now yield 401
api_call \
  "User: /auth/me/ after logout should be 401" \
  "GET" "/auth/me/" "401" "" "${NEW_USER_ACCESS}"

# 7.3 Soft delete: register a fresh QA-only user and delete them

QA_EMAIL="qa_$(date +%s)@example.com"
QA_REGISTER_PAYLOAD=$(cat <<EOF
{
  "email": "${QA_EMAIL}",
  "password": "QaPass123!",
  "repeat_password": "QaPass123!",
  "first_name": "QA"
}
EOF
)

api_call \
  "QA user registration" \
  "POST" "/auth/register/" "201" \
  "${QA_REGISTER_PAYLOAD}"

api_call \
  "QA user login" \
  "POST" "/auth/login/" "200" \
  "{\"email\":\"${QA_EMAIL}\",\"password\":\"QaPass123!\"}"

QA_ACCESS=$(echo "${LAST_BODY}" | jq -r '.data.access')

api_call \
  "QA user soft delete (DELETE /auth/me/)" \
  "DELETE" "/auth/me/" "204" "" "${QA_ACCESS}"

# Afterwards, login for same QA user should fail with 401
api_call \
  "QA user login after soft delete (expect 401)" \
  "POST" "/auth/login/" "401" \
  "{\"email\":\"${QA_EMAIL}\",\"password\":\"QaPass123!\"}"

###############################################################################
# Done
###############################################################################

echo
echo "=== QA walkthrough completed successfully. All checks passed. ==="
