#!/usr/bin/env bash
# Bash test suite for AWS KMS ML-DSA (FIPS 204). Requires: aws CLI v2, base64, head, openssl (offline tests need >= 3.5).
#
# Usage:
#   bash 04-test-kms-mldsa.sh                    # on the EC2 instance: key ID and Region read from demo.env
#   STACK_NAME=my-stack AWS_REGION=eu-west-3 bash 04-test-kms-mldsa.sh   # from a workstation: key ID from the stack
#   KEY_ID=<key id or alias> AWS_REGION=eu-west-3 bash 04-test-kms-mldsa.sh
#
# Exit code: 0 = all tests passed (skips allowed), 1 = at least one failure.

set -u

STACK_NAME="${STACK_NAME:-kms-mldsa-demo}"
DEMO_ENV="${DEMO_ENV:-/opt/kms-mldsa-demo/demo.env}"
envval() { [ -r "$DEMO_ENV" ] && grep "^$1=" "$DEMO_ENV" | head -1 | cut -d= -f2-; }
export AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(envval AWS_REGION)}}"
export AWS_REGION="${AWS_REGION:-eu-west-3}"
KEY_ID="${KEY_ID:-$(envval ML_DSA_KEY_ID)}"
ALG="ML_DSA_SHAKE_256"

PASS=0; FAIL=0; SKIP=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass() { PASS=$((PASS + 1)); echo "[PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $1"; [ -n "${2:-}" ] && echo "       $2"; }
skip() { SKIP=$((SKIP + 1)); echo "[SKIP] $1"; }
section() { echo; echo "== $1 =="; }

# kms <args...>: run an aws kms command; stdout+stderr in $OUT, exit code in $RC
kms() { OUT="$(aws kms "$@" 2>&1)"; RC=$?; }

# ---------------------------------------------------------------- prerequisites
section "0. Prerequisites"
for bin in aws base64 head; do
  command -v "$bin" >/dev/null 2>&1 || { echo "Missing required command: $bin"; exit 1; }
done
echo "aws: $(aws --version 2>&1 | head -1)"
echo "region: $AWS_REGION"

if [ -z "$KEY_ID" ]; then
  KEY_ID="$(aws cloudformation describe-stacks --region "$AWS_REGION" --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='MlDsaKeyId'].OutputValue" --output text 2>/dev/null)"
fi
if [ -z "$KEY_ID" ] || [ "$KEY_ID" = "None" ]; then
  echo "Cannot determine the ML-DSA key. Set KEY_ID, or STACK_NAME/AWS_REGION (or run on the demo instance)."
  exit 1
fi
echo "key: $KEY_ID"

# ---------------------------------------------------------------- 1. key metadata
section "1. Key configuration"
kms describe-key --key-id "$KEY_ID" --query 'KeyMetadata.[KeySpec,KeyUsage,KeyState]' --output text
if [ $RC -ne 0 ]; then
  fail "DescribeKey" "$OUT"
  echo; echo "Cannot continue without a readable key."; exit 1
fi
read -r KEY_SPEC KEY_USAGE KEY_STATE <<<"$OUT"

case "$KEY_SPEC" in
  ML_DSA_44) SIG_LEN=2420; PK_LEN=1312 ;;
  ML_DSA_65) SIG_LEN=3309; PK_LEN=1952 ;;
  ML_DSA_87) SIG_LEN=4627; PK_LEN=2592 ;;
  *) SIG_LEN=0; PK_LEN=0 ;;
esac

[ "$SIG_LEN" -ne 0 ] && pass "KeySpec is an ML-DSA spec ($KEY_SPEC)" || fail "KeySpec is an ML-DSA spec" "got: $KEY_SPEC"
[ "$KEY_USAGE" = "SIGN_VERIFY" ] && pass "KeyUsage is SIGN_VERIFY" || fail "KeyUsage is SIGN_VERIFY" "got: $KEY_USAGE"
[ "$KEY_STATE" = "Enabled" ] && pass "KeyState is Enabled" || fail "KeyState is Enabled" "got: $KEY_STATE"

kms describe-key --key-id "$KEY_ID" --query 'KeyMetadata.SigningAlgorithms' --output text
case "$OUT" in
  *"$ALG"*) pass "Key advertises signing algorithm $ALG" ;;
  *) fail "Key advertises signing algorithm $ALG" "got: $OUT" ;;
esac

# ---------------------------------------------------------------- 2. RAW signature
section "2. Sign / verify (RAW)"
head -c 256 /dev/urandom > "$TMP/msg.bin"

kms sign --key-id "$KEY_ID" --message "fileb://$TMP/msg.bin" --message-type RAW \
  --signing-algorithm "$ALG" --query Signature --output text
if [ $RC -eq 0 ]; then
  printf '%s' "$OUT" | base64 --decode > "$TMP/sig.bin"
  pass "KMS Sign (RAW) succeeds"
  ACTUAL_LEN="$(wc -c < "$TMP/sig.bin" | tr -d ' ')"
  [ "$ACTUAL_LEN" = "$SIG_LEN" ] && pass "Signature length is $SIG_LEN bytes" \
    || fail "Signature length is $SIG_LEN bytes" "got: $ACTUAL_LEN"
else
  fail "KMS Sign (RAW) succeeds" "$OUT"
  echo; echo "Cannot continue without a signature."; exit 1
fi

kms verify --key-id "$KEY_ID" --message "fileb://$TMP/msg.bin" --message-type RAW \
  --signing-algorithm "$ALG" --signature "fileb://$TMP/sig.bin" --query SignatureValid --output text
[ $RC -eq 0 ] && [ "$OUT" = "True" ] && pass "KMS Verify accepts the signature" \
  || fail "KMS Verify accepts the signature" "$OUT"

# ---------------------------------------------------------------- 3. negative tests
section "3. Negative tests"
cp "$TMP/msg.bin" "$TMP/tampered.bin"; printf 'x' >> "$TMP/tampered.bin"
kms verify --key-id "$KEY_ID" --message "fileb://$TMP/tampered.bin" --message-type RAW \
  --signing-algorithm "$ALG" --signature "fileb://$TMP/sig.bin" --query SignatureValid --output text
if [ $RC -ne 0 ] && printf '%s' "$OUT" | grep -q "KMSInvalidSignatureException"; then
  pass "Tampered message is rejected (KMSInvalidSignatureException)"
elif [ $RC -eq 0 ] && [ "$OUT" = "False" ]; then
  pass "Tampered message is rejected (SignatureValid=False)"
else
  fail "Tampered message is rejected" "rc=$RC out=$OUT"
fi

cp "$TMP/sig.bin" "$TMP/badsig.bin"
printf '\x00' | dd of="$TMP/badsig.bin" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
kms verify --key-id "$KEY_ID" --message "fileb://$TMP/msg.bin" --message-type RAW \
  --signing-algorithm "$ALG" --signature "fileb://$TMP/badsig.bin" --query SignatureValid --output text
if { [ $RC -ne 0 ] && printf '%s' "$OUT" | grep -q "KMSInvalidSignatureException"; } || [ "$OUT" = "False" ]; then
  pass "Corrupted signature is rejected"
else
  fail "Corrupted signature is rejected" "rc=$RC out=$OUT"
fi

kms sign --key-id "$KEY_ID" --message "fileb://$TMP/msg.bin" --message-type RAW \
  --signing-algorithm ECDSA_SHA_256 --query Signature --output text
[ $RC -ne 0 ] && pass "Classical algorithm ECDSA_SHA_256 is refused on an ML-DSA key" \
  || fail "Classical algorithm ECDSA_SHA_256 is refused on an ML-DSA key" "sign unexpectedly succeeded"

head -c 4097 /dev/urandom > "$TMP/big.bin"
kms sign --key-id "$KEY_ID" --message "fileb://$TMP/big.bin" --message-type RAW \
  --signing-algorithm "$ALG" --query Signature --output text
[ $RC -ne 0 ] && pass "RAW message larger than 4096 bytes is refused" \
  || fail "RAW message larger than 4096 bytes is refused" "sign unexpectedly succeeded"

head -c 32 /dev/urandom > "$TMP/short-mu.bin"
kms sign --key-id "$KEY_ID" --message "fileb://$TMP/short-mu.bin" --message-type EXTERNAL_MU \
  --signing-algorithm "$ALG" --query Signature --output text
[ $RC -ne 0 ] && pass "EXTERNAL_MU with a 32-byte message is refused (64 bytes required)" \
  || fail "EXTERNAL_MU with a 32-byte message is refused (64 bytes required)" "sign unexpectedly succeeded"

# ---------------------------------------------------------------- 4. public key
section "4. Public key"
kms get-public-key --key-id "$KEY_ID" --query PublicKey --output text
if [ $RC -eq 0 ]; then
  printf '%s' "$OUT" | base64 --decode > "$TMP/pub.der"
  PUB_LEN="$(wc -c < "$TMP/pub.der" | tr -d ' ')"
  pass "GetPublicKey succeeds ($PUB_LEN bytes DER SubjectPublicKeyInfo)"
  if [ "$PUB_LEN" -gt "$PK_LEN" ] && [ "$PUB_LEN" -lt $((PK_LEN + 64)) ]; then
    pass "Public key size matches $KEY_SPEC (raw key $PK_LEN bytes + DER header)"
  else
    fail "Public key size matches $KEY_SPEC" "DER length $PUB_LEN, raw key expected $PK_LEN"
  fi
else
  fail "GetPublicKey succeeds" "$OUT"
fi

# ---------------------------------------------------------------- 5. offline verification + external mu
section "5. Offline verification and EXTERNAL_MU (OpenSSL >= 3.5)"
OPENSSL_OK=0
if command -v openssl >/dev/null 2>&1; then
  OSSL_VER="$(openssl version | awk '{print $2}')"
  echo "openssl: $OSSL_VER"
  if [ "$(printf '%s\n3.5.0\n' "$OSSL_VER" | sort -V | head -1)" = "3.5.0" ]; then OPENSSL_OK=1; fi
fi

if [ "$OPENSSL_OK" -eq 1 ] && [ -s "$TMP/pub.der" ]; then
  openssl pkey -pubin -inform DER -in "$TMP/pub.der" -out "$TMP/pub.pem" 2>"$TMP/ossl.err"
  OUT="$(openssl pkeyutl -verify -pubin -inkey "$TMP/pub.pem" -rawin -in "$TMP/msg.bin" \
    -sigfile "$TMP/sig.bin" 2>&1)"; RC=$?
  [ $RC -eq 0 ] && pass "Offline OpenSSL verification of the KMS signature succeeds" \
    || fail "Offline OpenSSL verification of the KMS signature succeeds" "$OUT $(cat "$TMP/ossl.err")"

  OUT="$(openssl pkeyutl -verify -pubin -inkey "$TMP/pub.pem" -rawin -in "$TMP/tampered.bin" \
    -sigfile "$TMP/sig.bin" 2>&1)"; RC=$?
  [ $RC -ne 0 ] && pass "Offline OpenSSL verification rejects the tampered message" \
    || fail "Offline OpenSSL verification rejects the tampered message" "verification unexpectedly succeeded"

  # external mu (FIPS 204 section 6.2, pure ML-DSA, empty context):
  #   tr = SHAKE256(pk, 64);  mu = SHAKE256(tr || 0x00 || 0x00 || M, 64)
  tail -c "$PK_LEN" "$TMP/pub.der" > "$TMP/pk.raw"
  openssl dgst -shake256 -xoflen 64 -binary "$TMP/pk.raw" > "$TMP/tr.bin"
  { cat "$TMP/tr.bin"; printf '\x00\x00'; cat "$TMP/msg.bin"; } > "$TMP/mu-input.bin"
  openssl dgst -shake256 -xoflen 64 -binary "$TMP/mu-input.bin" > "$TMP/mu.bin"

  kms sign --key-id "$KEY_ID" --message "fileb://$TMP/mu.bin" --message-type EXTERNAL_MU \
    --signing-algorithm "$ALG" --query Signature --output text
  if [ $RC -eq 0 ]; then
    printf '%s' "$OUT" | base64 --decode > "$TMP/sig-mu.bin"
    pass "KMS Sign (EXTERNAL_MU) succeeds"
    kms verify --key-id "$KEY_ID" --message "fileb://$TMP/msg.bin" --message-type RAW \
      --signing-algorithm "$ALG" --signature "fileb://$TMP/sig-mu.bin" --query SignatureValid --output text
    [ $RC -eq 0 ] && [ "$OUT" = "True" ] \
      && pass "EXTERNAL_MU signature verifies in KMS against the original message (RAW)" \
      || fail "EXTERNAL_MU signature verifies in KMS against the original message (RAW)" "$OUT"
    OUT="$(openssl pkeyutl -verify -pubin -inkey "$TMP/pub.pem" -rawin -in "$TMP/msg.bin" \
      -sigfile "$TMP/sig-mu.bin" 2>&1)"; RC=$?
    [ $RC -eq 0 ] && pass "EXTERNAL_MU signature verifies offline with OpenSSL" \
      || fail "EXTERNAL_MU signature verifies offline with OpenSSL" "$OUT"
  else
    fail "KMS Sign (EXTERNAL_MU) succeeds" "$OUT"
  fi
else
  skip "Offline verification and EXTERNAL_MU need OpenSSL >= 3.5 (found: ${OSSL_VER:-none}); run them from a recent workstation"
fi

# ---------------------------------------------------------------- summary
section "Summary"
echo "passed: $PASS   failed: $FAIL   skipped: $SKIP"
if [ "$FAIL" -eq 0 ]; then echo "ALL TESTS PASSED"; exit 0; else echo "$FAIL TEST(S) FAILED"; exit 1; fi
