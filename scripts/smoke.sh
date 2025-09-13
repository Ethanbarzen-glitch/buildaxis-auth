#!/usr/bin/env bash
set -Eeuo pipefail

API=${API:-http://127.0.0.1:9001}
PRJ=${PRJ:-http://127.0.0.1:9010}
TEAMS=${TEAMS:-http://127.0.0.1:9020}
: "${API:?}"; : "${PRJ:?}"; : "${TEAMS:?}"

say() { printf "\n==> %s\n" "$*"; }
expect_code() {
  local got="$1" exp="$2" what="$3" body="$4"
  if [[ "$got" != "$exp" ]]; then
    echo "Expected $exp for $what, got $got"
    [[ -f "$body" ]] && { echo "-- body --"; cat "$body"; echo; echo "-- end --"; }
    exit 1
  fi
}
expect_one_of() {
  local got="$1" what="$2" body="$3"; shift 3
  for exp in "$@"; do [[ "$got" == "$exp" ]] && return 0; done
  echo "Expected one of [$*] for $what, got $got"
  [[ -f "$body" ]] && { echo "-- body --"; cat "$body"; echo; echo "-- end --"; }
  exit 1
}
curl_post_json() {
  # usage: curl_post_json <code_var_name> <url> <json_payload> <outfile>
  local __var="$1" __url="$2" __json="$3" __out="$4" __code
  __code=$(curl -sS -o "$__out" -w '%{http_code}' \
    -X POST "$__url" \
    -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
    -d "$__json")
  printf -v "$__var" '%s' "$__code"
}

say "Wait for services to be ready"
for i in {1..60}; do
  a=$(curl -sS -o /dev/null -w '%{http_code}' "$API/health"  || echo 000)
  p=$(curl -sS -o /dev/null -w '%{http_code}' "$PRJ/health"  || echo 000)
  t=$(curl -sS -o /dev/null -w '%{http_code}' "$TEAMS/health"|| echo 000)
  echo "try $i: api=$a projects=$p teams=$t"
  if [[ "$a" == 200 && "$p" == 200 && "$t" == 200 ]]; then
    echo "Services healthy"; break
  fi
  sleep 1
  [[ $i -eq 60 ]] && { echo "Services not healthy in time"; exit 1; }
done

# Login
USER=${ADMIN_USER:-admin}; PASS=${ADMIN_PASS:-adminpass}
say "Login (password grant)"
code=$(curl -sS -o /tmp/pair.json -w '%{http_code}' \
  -X POST "$API/token" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw "grant_type=password&username=${USER}&password=${PASS}&scope=")
expect_code "$code" 200 "login" /tmp/pair.json
ACCESS=$(jq -r .access_token /tmp/pair.json)

# Identities
say "Identity (projects)"
curl -sS -H "Authorization: Bearer $ACCESS" "$PRJ/me" | jq .
say "Identity (teams)"
curl -sS -H "Authorization: Bearer $ACCESS" "$TEAMS/me" | jq .

######## Projects ########
say "Projects: list (for info)"
curl -sS -H "Authorization: Bearer $ACCESS" "$PRJ/projects" | jq .

P_CODE="BA-HQ-$(date +%s)"
say "Projects: create $P_CODE"
curl_post_json code "$PRJ/projects" \
  "{\"name\":\"HQ Tower\",\"code\":\"$P_CODE\",\"description\":\"Flagship build\"}" \
  /tmp/p_create.json
expect_one_of "$code" "projects create" /tmp/p_create.json 200 201
jq . /tmp/p_create.json

say "Projects: duplicate should 409"
code=$(curl -sS -o /tmp/p_dup.json -w '%{http_code}' \
  -X POST "$PRJ/projects" \
  -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
  -d "{\"name\":\"HQ Tower\",\"code\":\"$P_CODE\",\"description\":\"Dup\"}")
expect_code "$code" 409 "projects duplicate" /tmp/p_dup.json
jq . /tmp/p_dup.json

say "Projects: get by code"
code=$(curl -sS -o /tmp/p_get.json -w '%{http_code}' \
  -H "Authorization: Bearer $ACCESS" "$PRJ/projects/$P_CODE")
expect_code "$code" 200 "projects get" /tmp/p_get.json
jq . /tmp/p_get.json

say "Projects: update"
code=$(curl -sS -o /tmp/p_put.json -w '%{http_code}' \
  -X PUT "$PRJ/projects/$P_CODE" \
  -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
  -d '{"description":"Updated desc"}')
expect_code "$code" 200 "projects update" /tmp/p_put.json
jq . /tmp/p_put.json

say "Projects: search"
curl -sS -H "Authorization: Bearer $ACCESS" \
  "$PRJ/projects?q=HQ&limit=10&offset=0" | jq .

say "Projects: delete"
code=$(curl -sS -o /tmp/p_del.json -w '%{http_code}' \
  -X DELETE "$PRJ/projects/$P_CODE" \
  -H "Authorization: Bearer $ACCESS")
expect_code "$code" 200 "projects delete" /tmp/p_del.json
jq . /tmp/p_del.json

######## Teams ########
T_CODE="BA-ALPHA-$(date +%s)"
say "Teams: create $T_CODE"
curl_post_json code "$TEAMS/teams" \
  "{\"name\":\"Alpha Team\",\"code\":\"$T_CODE\",\"description\":\"Core field crew\"}" \
  /tmp/t_create.json
expect_one_of "$code" "teams create" /tmp/t_create.json 200 201
jq . /tmp/t_create.json

say "Teams: duplicate should 409"
code=$(curl -sS -o /tmp/t_dup.json -w '%{http_code}' \
  -X POST "$TEAMS/teams" \
  -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
  -d "{\"name\":\"Alpha Team\",\"code\":\"$T_CODE\",\"description\":\"Dup\"}")
expect_code "$code" 409 "teams duplicate" /tmp/t_dup.json
jq . /tmp/t_dup.json

say "Teams: get by code"
code=$(curl -sS -o /tmp/t_get.json -w '%{http_code}' \
  -H "Authorization: Bearer $ACCESS" "$TEAMS/teams/$T_CODE")
expect_code "$code" 200 "teams get" /tmp/t_get.json
jq . /tmp/t_get.json

say "Teams: update"
code=$(curl -sS -o /tmp/t_put.json -w '%{http_code}' \
  -X PUT "$TEAMS/teams/$T_CODE" \
  -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
  -d '{"description":"Updated desc"}')
expect_code "$code" 200 "teams update" /tmp/t_put.json
jq . /tmp/t_put.json

say "Teams: search"
curl -sS -H "Authorization: Bearer $ACCESS" \
  "$TEAMS/teams?q=Alpha&limit=10&offset=0" | jq .

say "Teams: delete"
code=$(curl -sS -o /tmp/t_del.json -w '%{http_code}' \
  -X DELETE "$TEAMS/teams/$T_CODE" \
  -H "Authorization: Bearer $ACCESS")
expect_code "$code" 200 "teams delete" /tmp/t_del.json
jq . /tmp/t_del.json

echo
echo "✅ SMOKE PASS"
