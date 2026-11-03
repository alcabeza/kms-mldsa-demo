#!/usr/bin/env bash
# 03 - Measure KMS ML-DSA performance FROM the EC2 instance (run in an SSM session).
#   bash 03-benchmark-kms-mldsa.sh
#   RUNS=5 ITERATIONS=500 WARMUP=50 bash 03-benchmark-kms-mldsa.sh
#
# What it does:
#   1. Records the environment (instance type, AZ, Java).
#   2. Probes the KMS endpoint (TCP connect, TLS handshake) with curl: the cost of a new connection.
#   3. Runs the Java benchmark RUNS times (KMS Sign, KMS Verify, local Verify; ML-DSA vs ECDSA P-256).
#   4. Pools all samples and prints mean/p50/p95/p99/max per operation, run-to-run spread of p50,
#      and the ML-DSA vs ECDSA comparison. Raw CSV and summary go to $OUTDIR.
#
# Notes: KMS Sign/Verify are measured sequentially (one request at a time, SDK connection reuse),
# so this is latency, not throughput. Request quotas may throttle high-rate parallel use.

set -u
[ "$(id -u)" -eq 0 ] || exec sudo -E bash "$0" "$@"

DEMO_DIR="${DEMO_DIR:-/opt/kms-mldsa-demo}"
JAVA_HOME_DIR="${JAVA_HOME_DIR:-/usr/lib/jvm/java-25-amazon-corretto}"
MAVEN_DIR="${MAVEN_DIR:-/opt/apache-maven}"
RUNS="${RUNS:-3}"
ITERATIONS="${ITERATIONS:-300}"
WARMUP="${WARMUP:-30}"
PROBES="${PROBES:-20}"
OUTDIR="${OUTDIR:-/var/tmp/kms-mldsa-perf-$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$OUTDIR" || { echo "Cannot create $OUTDIR"; exit 1; }
exec > >(tee "$OUTDIR/summary.txt") 2>&1

[ -r "$DEMO_DIR/demo.env" ] || { echo "Missing $DEMO_DIR/demo.env (run 01-verify-install.sh)"; exit 1; }
[ -x "$MAVEN_DIR/bin/mvn" ] || { echo "Missing Maven ($MAVEN_DIR)"; exit 1; }

# ---------- helpers ----------
median() { sort -n | awk '{a[NR]=$1} END{ if(NR==0){print "n/a"} else {print a[int((NR+1)/2)]} }'; }

# stats <file with one value per line, sorted ascending>  -> "mean p50 p95 p99 max"
stats() {
  awk '{a[NR]=$1; s+=$1}
       function pct(p,  i){ i=int(p/100*NR); if(i<p/100*NR) i++; if(i<1)i=1; if(i>NR)i=NR; return a[i] }
       END{ if(NR==0){print "nan nan nan nan nan"; exit}
            printf "%.2f %.2f %.2f %.2f %.2f\n", s/NR, pct(50), pct(95), pct(99), a[NR] }'
}

# ---------- 1. environment ----------
echo "== 1. Environment =="
TOKEN="$(curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')"
imds() { curl -s -m 3 -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
set -a; . "$DEMO_DIR/demo.env"; set +a
echo "date:       $(date -u +%FT%TZ)"
echo "instance:   $(imds instance-id) ($(imds instance-type)), az $(imds placement/availability-zone)"
echo "region:     $AWS_REGION"
echo "java:       $("$JAVA_HOME_DIR/bin/java" -version 2>&1 | head -1)"
echo "parameters: RUNS=$RUNS ITERATIONS=$ITERATIONS WARMUP=$WARMUP (each run: 3 operations x 2 keys)"
echo "output:     $OUTDIR"

# ---------- 2. endpoint probe ----------
echo
echo "== 2. KMS endpoint probe (new connection each time, $PROBES probes) =="
EP="https://kms.${AWS_REGION}.amazonaws.com/"
: > "$OUTDIR/probe.txt"
for _ in $(seq 1 "$PROBES"); do
  curl -s -m 8 -o /dev/null -w '%{time_connect} %{time_appconnect}\n' "$EP" >> "$OUTDIR/probe.txt"
done
TCP_MS="$(awk '{printf "%.2f\n",$1*1000}' "$OUTDIR/probe.txt" | median)"
TLS_MS="$(awk '{printf "%.2f\n",($2-$1)*1000}' "$OUTDIR/probe.txt" | median)"
echo "TCP connect (median):          ${TCP_MS} ms"
echo "TLS handshake (median):        ${TLS_MS} ms   <- connection setup cost; absent on reused connections"
echo "(The TLS key exchange group used depends on the client library; the Java SDK demo reuses connections.)"

# ---------- 3. benchmark runs ----------
echo
echo "== 3. Java benchmark runs =="
export JAVA_HOME="$JAVA_HOME_DIR"
export PATH="$JAVA_HOME/bin:$MAVEN_DIR/bin:$PATH"
OKRUNS=0
for i in $(seq 1 "$RUNS"); do
  echo "-- run $i/$RUNS"
  rm -f "$DEMO_DIR/results.csv"
  if ( cd "$DEMO_DIR" && ITERATIONS="$ITERATIONS" WARMUP="$WARMUP" mvn -q -B exec:java ) \
       > "$OUTDIR/run-$i.log" 2>&1; then
    if [ -s "$DEMO_DIR/results.csv" ]; then
      mv "$DEMO_DIR/results.csv" "$OUTDIR/results-run$i.csv"
      OKRUNS=$((OKRUNS + 1))
      grep -q 'ALL CHECKS PASSED' "$OUTDIR/run-$i.log" || echo "   warning: functional checks did not all pass (see run-$i.log)"
      echo "   ok -> results-run$i.csv"
    else
      echo "   run finished but no results.csv (see run-$i.log)"
    fi
  else
    echo "   FAILED (see $OUTDIR/run-$i.log)"; tail -5 "$OUTDIR/run-$i.log"
  fi
done
[ "$OKRUNS" -gt 0 ] || { echo "No successful run."; exit 1; }

echo "operation,iteration,ms" > "$OUTDIR/results-all.csv"
for f in "$OUTDIR"/results-run*.csv; do tail -n +2 "$f" >> "$OUTDIR/results-all.csv"; done

# ---------- 4. statistics ----------
echo
echo "== 4. Latency per operation (ms), pooled over $OKRUNS run(s) =="
printf '%-26s %7s %8s %8s %8s %8s %8s\n' operation n mean p50 p95 p99 max
declare -A P50 P95
OPS="$(tail -n +2 "$OUTDIR/results-all.csv" | cut -d, -f1 | awk '!seen[$0]++')"
while IFS= read -r op; do
  [ -n "$op" ] || continue
  awk -F, -v op="$op" '$1==op {print $3}' "$OUTDIR/results-all.csv" | sort -n > "$OUTDIR/.vals"
  n="$(wc -l < "$OUTDIR/.vals" | tr -d ' ')"
  read -r mean p50 p95 p99 max <<<"$(stats < "$OUTDIR/.vals")"
  printf '%-26s %7s %8s %8s %8s %8s %8s\n' "$op" "$n" "$mean" "$p50" "$p95" "$p99" "$max"
  P50["$op"]="$p50"; P95["$op"]="$p95"
done <<<"$OPS"
rm -f "$OUTDIR/.vals"

echo
echo "== 5. Run-to-run stability (p50 per run, ms) =="
while IFS= read -r op; do
  [ -n "$op" ] || continue
  line=""
  for f in "$OUTDIR"/results-run*.csv; do
    v="$(awk -F, -v op="$op" '$1==op {print $3}' "$f" | sort -n | stats | awk '{print $2}')"
    line="$line $v"
  done
  printf '%-26s%s\n' "$op" "$line"
done <<<"$OPS"

echo
echo "== 6. ML-DSA vs ECDSA P-256 (ratio of ML-DSA to ECDSA) =="
printf '%-18s %10s %10s %8s | %10s %10s %8s\n' operation "ML p50" "EC p50" ratio "ML p95" "EC p95" ratio
for kind in "KMS Sign" "KMS Verify" "local Verify"; do
  m50="${P50["ML-DSA $kind"]:-}"; e50="${P50["ECDSA-P256 $kind"]:-}"
  m95="${P95["ML-DSA $kind"]:-}"; e95="${P95["ECDSA-P256 $kind"]:-}"
  if [ -n "$m50" ] && [ -n "$e50" ]; then
    r50="$(awk -v a="$m50" -v b="$e50" 'BEGIN{ if(b>0) printf "%.2fx", a/b; else print "n/a" }')"
    r95="$(awk -v a="$m95" -v b="$e95" 'BEGIN{ if(b>0) printf "%.2fx", a/b; else print "n/a" }')"
    printf '%-18s %10s %10s %8s | %10s %10s %8s\n' "$kind" "$m50" "$e50" "$r50" "$m95" "$e95" "$r95"
  fi
done
echo
echo "Interpretation: compare p50 AND p95/p99; KMS time is dominated by network + HSM, so small gaps"
echo "between algorithms are expected. Signature sizes (ML-DSA vs ECDSA) are printed in run-1.log."
echo "Files: $OUTDIR/{summary.txt,results-all.csv,results-run*.csv,run-*.log,probe.txt}"
