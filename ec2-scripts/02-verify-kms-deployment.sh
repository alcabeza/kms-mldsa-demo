#!/usr/bin/env bash
# 02 - Verify that the KMS ML-DSA deployment is usable FROM the instance (run in an SSM session).
#   bash 02-verify-kms-deployment.sh
# Read-only except for Sign/Verify calls on the two demo keys. Exit code: 0 = no failure, 1 = failure.

set -u
[ "$(id -u)" -eq 0 ] || exec sudo -E bash "$0" "$@"

DEMO_DIR="${DEMO_DIR:-/opt/kms-mldsa-demo}"
DEMO_LOG="${DEMO_LOG:-/var/log/kms-mldsa-demo.log}"
if [ -r "$DEMO_DIR/demo.env" ]; then set -a; . "$DEMO_DIR/demo.env"; set +a; fi
export AWS_REGION="${AWS_REGION:-}"

PASS=0; FAIL=0; WARN=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass() { PASS=$((PASS + 1)); echo "[PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $1"; [ -n "${2:-}" ] && echo "       $2"; }
warn() { WARN=$((WARN + 1)); echo "[WARN] $1"; [ -n "${2:-}" ] && echo "       $2"; }
section() { echo; echo "== $1 =="; }
kms() { OUT="$(aws kms "$@" 2>&1)"; RC=$?; }

section "0. Context"
for v in AWS_REGION ML_DSA_KEY_ID ECDSA_KEY_ID; do
  [ -n "${!v:-}" ] && echo "$v=${!v}" || { fail "$v is set (from $DEMO_DIR/demo.env)"; }
done
[ "$FAIL" -eq 0 ] || { echo "Cannot continue."; exit 1; }
ID="$(aws sts get-caller-identity --query Arn --output text 2>&1)"
case "$ID" in *assumed-role*) pass "Caller identity: $ID" ;; *) fail "Caller identity" "$ID"; exit 1 ;; esac

check_key() { # label keyid expected_spec_regex expected_alg
  local label="$1" key="$2" spec_re="$3" alg="$4"
  kms describe-key --key-id "$key" \
    --query 'KeyMetadata.[KeySpec,KeyUsage,KeyState,Origin,KeyManager]' --output text
  if [ $RC -ne 0 ]; then fail "$label: DescribeKey" "$OUT"; return 1; fi
  local spec usage state origin manager
  read -r spec usage state origin manager <<<"$OUT"
  [[ "$spec" =~ $spec_re ]] && pass "$label: KeySpec $spec" || fail "$label: KeySpec" "got $spec, expected $spec_re"
  [ "$usage" = "SIGN_VERIFY" ] && pass "$label: KeyUsage SIGN_VERIFY" || fail "$label: KeyUsage" "got $usage"
  [ "$state" = "Enabled" ] && pass "$label: KeyState Enabled" || fail "$label: KeyState" "got $state"
  [ "$origin" = "AWS_KMS" ] && pass "$label: key material generated in AWS KMS (never exportable)" || warn "$label: Origin" "$origin"
  [ "$manager" = "CUSTOMER" ] && pass "$label: customer managed key" || warn "$label: KeyManager" "$manager"
  kms describe-key --key-id "$key" --query 'KeyMetadata.SigningAlgorithms' --output text
  case "$OUT" in *"$alg"*) pass "$label: signing algorithm $alg advertised" ;; *) fail "$label: signing algorithm $alg" "got: $OUT" ;; esac
}

section "1. ML-DSA key"
check_key "ML-DSA" "$ML_DSA_KEY_ID" '^ML_DSA_(44|65|87)$' ML_DSA_SHAKE_256
section "2. ECDSA P-256 baseline key"
check_key "ECDSA" "$ECDSA_KEY_ID" '^ECC_NIST_P256$' ECDSA_SHA_256

smoke() { # label keyid alg expected_min_sig_len
  local label="$1" key="$2" alg="$3" min="$4"
  head -c 64 /dev/urandom > "$TMP/m.bin"
  kms sign --key-id "$key" --message "fileb://$TMP/m.bin" --message-type RAW --signing-algorithm "$alg" \
    --query Signature --output text
  if [ $RC -ne 0 ]; then fail "$label: Sign" "$OUT"; return; fi
  printf '%s' "$OUT" | base64 --decode > "$TMP/s.bin"
  local len; len="$(wc -c < "$TMP/s.bin" | tr -d ' ')"
  [ "$len" -ge "$min" ] && pass "$label: Sign OK ($len-byte signature)" || fail "$label: signature length" "$len < $min"
  kms verify --key-id "$key" --message "fileb://$TMP/m.bin" --message-type RAW --signing-algorithm "$alg" \
    --signature "fileb://$TMP/s.bin" --query SignatureValid --output text
  [ $RC -eq 0 ] && [ "$OUT" = "True" ] && pass "$label: Verify OK" || fail "$label: Verify" "$OUT"
  kms get-public-key --key-id "$key" --query PublicKey --output text
  [ $RC -eq 0 ] && pass "$label: GetPublicKey OK ($(printf '%s' "$OUT" | base64 --decode | wc -c | tr -d ' ') bytes DER)" \
    || fail "$label: GetPublicKey" "$OUT"
}

section "3. Smoke tests (Sign / Verify / GetPublicKey)"
smoke "ML-DSA" "$ML_DSA_KEY_ID" ML_DSA_SHAKE_256 2420
smoke "ECDSA" "$ECDSA_KEY_ID" ECDSA_SHA_256 64

section "4. Least privilege (the instance role must NOT do more than needed)"
kms list-keys --limit 1
[ $RC -ne 0 ] && printf '%s' "$OUT" | grep -qi 'AccessDenied' \
  && pass "kms:ListKeys is denied" || warn "kms:ListKeys is denied" "rc=$RC (role may be broader than the demo policy)"
kms get-key-rotation-status --key-id "$ML_DSA_KEY_ID"
[ $RC -ne 0 ] && printf '%s' "$OUT" | grep -qi 'AccessDenied' \
  && pass "kms:GetKeyRotationStatus is denied" || warn "kms:GetKeyRotationStatus is denied" "rc=$RC"

section "5. Endpoint"
EP="https://kms.${AWS_REGION}.amazonaws.com/"
T="$(curl -s -m 8 -o /dev/null -w '%{time_connect} %{time_appconnect} %{http_code}' "$EP")"
read -r tc ta code <<<"$T"
[ "$code" != "000" ] && pass "KMS endpoint reachable ($EP, HTTP $code, TCP ${tc}s, TLS done at ${ta}s)" || fail "KMS endpoint reachable" "$EP"

section "6. Java demo outcome"
if [ -s "$DEMO_LOG" ] && grep -q 'ALL CHECKS PASSED' "$DEMO_LOG"; then
  pass "Java demo log reports ALL CHECKS PASSED"
else
  warn "Java demo log reports ALL CHECKS PASSED" "$DEMO_LOG missing or failed"
fi

section "Summary"
echo "passed: $PASS   failed: $FAIL   warnings: $WARN"
if [ "$FAIL" -eq 0 ]; then echo "KMS ML-DSA DEPLOYMENT OK"; exit 0; else echo "KMS ML-DSA DEPLOYMENT HAS $FAIL FAILURE(S)"; exit 1; fi
