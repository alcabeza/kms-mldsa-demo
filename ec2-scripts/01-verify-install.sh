#!/usr/bin/env bash
# 01 - Verify that the EC2 instance installation is complete (run ON the instance, e.g. in an SSM session).
#   bash 01-verify-install.sh
# Exit code: 0 = no failure (warnings allowed), 1 = at least one failure.

set -u
[ "$(id -u)" -eq 0 ] || exec sudo -E bash "$0" "$@"

DEMO_DIR="${DEMO_DIR:-/opt/kms-mldsa-demo}"
JAVA_HOME_DIR="${JAVA_HOME_DIR:-/usr/lib/jvm/java-25-amazon-corretto}"
MAVEN_DIR="${MAVEN_DIR:-/opt/apache-maven}"
DEMO_LOG="${DEMO_LOG:-/var/log/kms-mldsa-demo.log}"
USERDATA_LOG="${USERDATA_LOG:-/var/log/kms-mldsa-userdata.log}"
DONE_MARKER="${DONE_MARKER:-/var/log/kms-mldsa-demo.done}"

PASS=0; FAIL=0; WARN=0
pass() { PASS=$((PASS + 1)); echo "[PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "[FAIL] $1"; [ -n "${2:-}" ] && echo "       $2"; }
warn() { WARN=$((WARN + 1)); echo "[WARN] $1"; [ -n "${2:-}" ] && echo "       $2"; }
section() { echo; echo "== $1 =="; }
have() { command -v "$1" >/dev/null 2>&1; }

section "1. Instance and metadata (IMDSv2)"
TOKEN="$(curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)"
imds() { curl -s -m 3 -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1" 2>/dev/null; }
if [ -n "$TOKEN" ]; then
  pass "IMDSv2 token obtained"
  echo "       instance-id=$(imds instance-id) type=$(imds instance-type) az=$(imds placement/availability-zone)"
else
  fail "IMDSv2 token obtained" "metadata service unreachable"
fi
CODE="$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)"
[ "$CODE" = "401" ] && pass "IMDSv1 is refused (HTTP 401)" || warn "IMDSv1 is refused" "got HTTP $CODE (expected 401)"
if [ -r /etc/os-release ] && grep -q 'Amazon Linux' /etc/os-release && grep -q 'VERSION_ID="2023"' /etc/os-release; then
  pass "OS is Amazon Linux 2023"
else
  warn "OS is Amazon Linux 2023" "$(grep PRETTY_NAME /etc/os-release 2>/dev/null)"
fi
if have timedatectl && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then
  pass "Clock is NTP-synchronized (required for SigV4)"
else
  warn "Clock is NTP-synchronized (required for SigV4)" "check chronyd"
fi

section "2. Boot sequence (cloud-init, user data, cfn-init)"
if have cloud-init; then
  CI="$(cloud-init status 2>&1 | head -1)"
  case "$CI" in *done*) pass "cloud-init finished ($CI)" ;; *) fail "cloud-init finished" "$CI" ;; esac
fi
[ -s "$USERDATA_LOG" ] && pass "User-data log exists ($USERDATA_LOG)" || fail "User-data log exists" "$USERDATA_LOG missing or empty"
if [ -s "$USERDATA_LOG" ]; then
  grep -q '== cfn-init' "$USERDATA_LOG" && pass "cfn-init step reached" || fail "cfn-init step reached"
  if grep -Eq 'BUILD FAILURE|No match for argument|Traceback|Could not resolve' "$USERDATA_LOG"; then
    fail "No fatal error pattern in user-data log" "$(grep -E 'BUILD FAILURE|No match for argument|Traceback|Could not resolve' "$USERDATA_LOG" | head -3)"
  else
    pass "No fatal error pattern in user-data log"
  fi
fi
[ -x /opt/aws/bin/cfn-init ] && pass "aws-cfn-bootstrap installed" || fail "aws-cfn-bootstrap installed"
[ -e "$DONE_MARKER" ] && pass "Completion marker present ($DONE_MARKER)" \
  || fail "Completion marker present" "installation still running? tail -f $USERDATA_LOG"

section "3. Toolchain"
if [ -x "$JAVA_HOME_DIR/bin/javac" ]; then
  JV="$("$JAVA_HOME_DIR/bin/java" -version 2>&1 | head -1)"
  case "$JV" in *'"25'*) pass "JDK 25 (Corretto) installed: $JV" ;; *) fail "JDK 25 installed" "$JV" ;; esac
else
  fail "JDK 25 installed" "$JAVA_HOME_DIR/bin/javac not found"
fi
if [ -x "$MAVEN_DIR/bin/mvn" ]; then
  # JDK 24+ prints "WARNING: A restricted method..." on stderr before the version: pick the right line
  MVOUT="$(JAVA_HOME=$JAVA_HOME_DIR "$MAVEN_DIR/bin/mvn" -v 2>&1)"
  MV="$(printf '%s\n' "$MVOUT" | grep -m1 'Apache Maven')"
  case "$MV" in *'Apache Maven 3.'*) pass "Maven installed: $MV" ;; *) fail "Maven installed" "$(printf '%s\n' "$MVOUT" | head -3)" ;; esac
else
  fail "Maven installed" "$MAVEN_DIR/bin/mvn not found"
fi
if have aws; then pass "AWS CLI installed: $(aws --version 2>&1 | head -1)"; else warn "AWS CLI installed" "needed by scripts 02"; fi
have curl && pass "curl installed" || fail "curl installed"

section "4. Demo files (written by cfn-init)"
for f in demo.env run-demo.sh pom.xml src/main/java/demo/KmsMlDsaDemo.java; do
  [ -s "$DEMO_DIR/$f" ] && pass "$f present" || fail "$f present" "$DEMO_DIR/$f missing or empty"
done
[ -x "$DEMO_DIR/run-demo.sh" ] && pass "run-demo.sh is executable" || fail "run-demo.sh is executable"
if [ -r "$DEMO_DIR/demo.env" ]; then
  for v in AWS_REGION ML_DSA_KEY_ID ECDSA_KEY_ID ITERATIONS WARMUP; do
    val="$(grep "^$v=" "$DEMO_DIR/demo.env" | cut -d= -f2-)"
    [ -n "$val" ] && pass "demo.env defines $v ($val)" || fail "demo.env defines $v"
  done
fi

section "5. Build"
[ -s "$DEMO_DIR/target/classes/demo/KmsMlDsaDemo.class" ] && pass "KmsMlDsaDemo compiled" \
  || fail "KmsMlDsaDemo compiled" "target/classes/demo/KmsMlDsaDemo.class missing"
if find /root/.m2/repository/software/amazon/awssdk/kms -name '*.jar' 2>/dev/null | grep -q .; then
  pass "AWS SDK KMS dependency downloaded"
else
  fail "AWS SDK KMS dependency downloaded" "/root/.m2 has no kms jar"
fi
find /root/.m2/repository/org/bouncycastle/bcprov-jdk18on -name '*.jar' 2>/dev/null | grep -q . \
  && pass "BouncyCastle dependency downloaded" || fail "BouncyCastle dependency downloaded"

section "6. Demo execution result"
if [ -s "$DEMO_LOG" ]; then
  grep -q 'ALL CHECKS PASSED' "$DEMO_LOG" && pass "Demo reported ALL CHECKS PASSED" \
    || fail "Demo reported ALL CHECKS PASSED" "see $DEMO_LOG"
  grep -q 'demo exit code: 0' "$DEMO_LOG" && pass "Demo exit code is 0" \
    || fail "Demo exit code is 0" "$(grep 'demo exit code' "$DEMO_LOG")"
  [ -s "$DEMO_DIR/results.csv" ] && pass "results.csv written ($(wc -l < "$DEMO_DIR/results.csv") lines)" \
    || warn "results.csv written" "missing (moved by script 03?)"
else
  fail "Demo log present" "$DEMO_LOG missing or empty"
fi

section "7. Connectivity and credentials"
for url in "https://kms.${AWS_REGION:-$(imds placement/region)}.amazonaws.com/" https://repo.maven.apache.org/maven2/; do
  code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' "$url")"
  { [ "$code" != "000" ] && [ -n "$code" ]; } && pass "Reachable: $url (HTTP $code)" || fail "Reachable: $url"
done
if have aws; then
  ID="$(aws sts get-caller-identity --query Arn --output text 2>&1)"
  case "$ID" in *assumed-role*) pass "Instance role credentials work: $ID" ;; *) fail "Instance role credentials work" "$ID" ;; esac
fi

section "Summary"
echo "passed: $PASS   failed: $FAIL   warnings: $WARN"
if [ "$FAIL" -eq 0 ]; then echo "INSTALLATION COMPLETE"; exit 0; else echo "INSTALLATION INCOMPLETE ($FAIL failure(s))"; exit 1; fi
