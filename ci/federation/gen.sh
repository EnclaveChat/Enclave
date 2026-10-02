#!/usr/bin/env bash
# Three operators' stacks on one host, federated by a test foundation
# (CI job `federation-e2e-tcp`; docs/13-operators.md).
#
#   ci/federation/gen.sh up      # build the federation and start it
#   ci/federation/gen.sh e2e     # run enclave-e2e against it (restarts B midway)
#   ci/federation/gen.sh logs    # every stack's logs (on failure)
#   ci/federation/gen.sh down    # stop everything and remove the volumes
#
# Needs: docker with compose, openssl, and the host binaries
# target/release/enclave-admin and target/release/enclave-e2e. The image is
# $IMAGE (default enclave-server:ci, built from ops/docker/Dockerfile).
#
# Each stack runs the real compose file with the development override
# (server reachable on 127.0.0.1) and the e2e override (witnesses on a shared
# network). The foundation key is made here; the list is built from the
# descriptors the stacks sign, the way the foundation builds it. Every log
# is witnessed by the other two stacks' witnesses, threshold 2.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$ROOT/target/federation}
IMAGE=${IMAGE:-enclave-server:ci}
ADMIN=${ADMIN:-$ROOT/target/release/enclave-admin}
E2E=${E2E:-$ROOT/target/release/enclave-e2e}
STACKS=(a b c)
PUSH_PORT=${PUSH_PORT:-8099}

dc() {
  local s=$1
  shift
  docker compose -p "e2e-$s" --project-directory "$WORK/$s" \
    -f "$WORK/$s/compose.yml" -f "$WORK/$s/compose.dev.yml" -f "$WORK/$s/compose.e2e.yml" "$@"
}

n_of() { case $1 in a) echo 1 ;; b) echo 2 ;; c) echo 3 ;; esac; }

wait_healthy() {
  local s=$1 i
  for i in $(seq 1 90); do
    if ! dc "$s" ps -a --format '{{.Health}}' | grep -qv healthy; then
      return 0
    fi
    sleep 2
  done
  dc "$s" ps
  dc "$s" logs --tail 50
  echo "stack $s did not become healthy" >&2
  return 1
}

up() {
  rm -rf "$WORK"
  mkdir -p "$WORK/foundation" "$WORK/tls"
  docker network create enclave-federation >/dev/null 2>&1 || true

  echo "== foundation key"
  "$ADMIN" foundation-keygen "$WORK/foundation.key" "$WORK/foundation/foundation.pub"

  echo "== a test CA for the fronts"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 2 \
    -subj "/CN=enclave e2e CA" -keyout "$WORK/tls/ca.key" -out "$WORK/tls/ca.pem" 2>/dev/null

  for s in "${STACKS[@]}"; do
    local n d others=() o
    n=$(n_of "$s")
    d=$WORK/$s
    mkdir -p "$d/config" "$d/foundation" "$d/tls" "$d/out"
    chmod 0777 "$d/out"
    cp "$ROOT"/ops/compose/compose.yml "$ROOT"/ops/compose/compose.dev.yml \
       "$ROOT"/ops/compose/compose.e2e.yml "$d/"
    for f in "$ROOT"/ops/compose/config/*.toml.example; do
      cp "$f" "$d/config/$(basename "${f%.example}")"
    done
    for o in "${STACKS[@]}"; do [ "$o" != "$s" ] && others+=("\"http://witness-$o:7446\""); done
    sed -i "s|^witnesses = \[\]|witnesses = [$(IFS=,; echo "${others[*]}")]|" "$d/config/server.toml"
    if [ "$s" = b ]; then
      printf '\n[push]\nforward = "push-relay:7445"\n' >> "$d/config/server.toml"
    fi
    cat >> "$d/config/front.toml" <<EOF
tls = "files"
cert = "/etc/enclave/tls/cert.pem"
key = "/etc/enclave/tls/key.pem"
EOF
    # The front's certificate, for 127.0.0.1 under the test CA.
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
      -subj "/CN=$s.test" -keyout "$d/tls/key.pem" -out "$d/tls/req.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1,DNS:%s.test\n' "$s" > "$d/tls/ext.cnf"
    openssl x509 -req -in "$d/tls/req.csr" -CA "$WORK/tls/ca.pem" -CAkey "$WORK/tls/ca.key" \
      -CAcreateserial -days 2 -extfile "$d/tls/ext.cnf" -out "$d/tls/cert.pem" 2>/dev/null
    chmod 0644 "$d/tls/key.pem"
    cat > "$d/.env" <<EOF
ENCLAVE_IMAGE=${IMAGE%:*}
ENCLAVE_VERSION=${IMAGE##*:}
STACK=$s
DOMAIN=$s.test
OPERATOR=op-$s
FAMILY=fam-$s
TLS_MODE=files
RELAY_PUBLIC_ADDR=127.0.0.1:5182$n
FRONT_HTTP_PORT=808$n
FRONT_HTTPS_PORT=844$n
RELAY_PORT=5182$n
SERVER_PORT=744$n
EOF
    cp "$WORK/foundation/foundation.pub" "$d/foundation/"

    echo "== stack $s: keys and descriptors"
    dc "$s" run --rm -T server init | tail -1 > "$d/server.id"
    dc "$s" run --rm -T witness init >/dev/null
    dc "$s" run --rm -T relay init >/dev/null
    dc "$s" run --rm -T -v "$d/out:/out" server descriptor /out/server.bin --config /etc/enclave/server.toml >/dev/null
    dc "$s" run --rm -T -v "$d/out:/out" witness descriptor /out/witness.bin --config /etc/enclave/witness.toml >/dev/null
    dc "$s" run --rm -T -v "$d/out:/out" relay descriptor /out/relay.bin --config /etc/enclave/relay.toml >/dev/null
    echo "   server $(cat "$d/server.id")"
  done

  echo "== push relay (stack b)"
  dc b run --rm -T push-relay init >/dev/null
  dc b --profile push up -d push-relay
  for _ in $(seq 1 30); do
    dc b cp push-relay:/var/lib/enclave/public/push-relay-keys.bin "$WORK/push-relay-keys.bin" 2>/dev/null && break
    sleep 1
  done
  test -s "$WORK/push-relay-keys.bin"

  echo "== the list"
  cat > "$WORK/spec.toml" <<EOF
seq = 1
valid_days = 7
witness_threshold = 2
EOF
  for s in "${STACKS[@]}"; do
    cat >> "$WORK/spec.toml" <<EOF
[[server]]
descriptor = "$s/out/server.bin"
weight = 1
[[witness]]
descriptor = "$s/out/witness.bin"
[[relay]]
descriptor = "$s/out/relay.bin"
EOF
  done
  cat >> "$WORK/spec.toml" <<EOF
[[push]]
nym_address = "e2e-push-relay"
keys = "push-relay-keys.bin"
EOF
  "$ADMIN" server-list build "$WORK/spec.toml" --key "$WORK/foundation.key" \
    --out "$WORK/foundation/server-list.bin"
  "$ADMIN" server-list verify "$WORK/foundation/server-list.bin" \
    --foundation "$WORK/foundation/foundation.pub"

  echo "== start"
  for s in "${STACKS[@]}"; do
    cp "$WORK/foundation/server-list.bin" "$WORK/$s/foundation/"
    if [ "$s" = b ]; then
      dc "$s" --profile push up -d
    else
      dc "$s" up -d
    fi
  done
  for s in "${STACKS[@]}"; do wait_healthy "$s"; done

  echo "== fronts serve their servers' descriptors over the Enclave TLS profile"
  for s in "${STACKS[@]}"; do
    "$ADMIN" descriptor fetch "https://127.0.0.1:844$(n_of "$s")" --ca "$WORK/tls/ca.pem" \
      --id "$(cat "$WORK/$s/server.id")" --out "$WORK/$s/fetched.bin"
  done
}

servers_arg() {
  local s out=()
  for s in "${STACKS[@]}"; do out+=("$(cat "$WORK/$s/server.id")=127.0.0.1:744$(n_of "$s")"); done
  IFS=,; echo "${out[*]}"
}

e2e() {
  local common=(--state "$WORK/e2e" --servers "$(servers_arg)"
    --foundation "$WORK/foundation/foundation.pub" --server-list "$WORK/foundation/server-list.bin")
  "$E2E" setup "${common[@]}" \
    --push-relay-keys "$WORK/push-relay-keys.bin" \
    --push-listen "0.0.0.0:$PUSH_PORT" \
    --push-endpoint "http://host.docker.internal:$PUSH_PORT/up"
  echo "== restarting stack b"
  dc b --profile push restart
  wait_healthy b
  "$E2E" after-restart "${common[@]}"
}

down() {
  for s in "${STACKS[@]}"; do
    [ -d "$WORK/$s" ] && dc "$s" --profile push down -v --remove-orphans || true
  done
  docker network rm enclave-federation >/dev/null 2>&1 || true
}

logs() {
  for s in "${STACKS[@]}"; do
    [ -d "$WORK/$s" ] && dc "$s" --profile push logs --no-color --tail 200 || true
  done
}

case "${1:-}" in
  up) up ;;
  e2e) e2e ;;
  logs) logs ;;
  down) down ;;
  *) echo "usage: $0 up|e2e|logs|down" >&2; exit 2 ;;
esac
