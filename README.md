# AWS KMS + ML-DSA (FIPS 204) – self-contained post-quantum signature demo

One CloudFormation template creates **everything**: the KMS keys, a small VPC, an EC2 instance that
installs JDK 25 + Maven, builds the Java demo (embedded in the template), runs it and keeps the results.
The verification, test and benchmark scripts are embedded too. Delete the stack and it all goes away.
**Step-by-step test guide from the instance: see `TUTORIAL.md`.**

What the demo does:
1. Describes the keys (key spec, signing algorithm `ML_DSA_SHAKE_256`).
2. Signs with KMS (`RAW`), verifies in KMS **and offline** with the JDK (native ML-DSA, JDK 24+).
3. Checks that a tampered message is rejected.
4. Signs with `EXTERNAL_MU` (mu computed client side with SHAKE256) and verifies it.
5. Benchmarks KMS Sign, KMS Verify and local Verify (mean, p50, p95, p99, max) for ML-DSA and an
   ECDSA P-256 baseline; writes `/opt/kms-mldsa-demo/results.csv`.

## Scripts available on the instance (`/opt/kms-mldsa-demo/scripts`)
| Script | Purpose |
|---|---|
| `01-verify-install.sh` | Checks that the instance installation is complete (JDK, Maven, files, build, demo result, connectivity) |
| `02-verify-kms-deployment.sh` | Checks the KMS keys and role from the instance (key specs, sign/verify smoke tests, least privilege) |
| `03-benchmark-kms-mldsa.sh` | Latency benchmark ML-DSA vs ECDSA P-256 (pooled runs, p50/p95/p99, endpoint probe) |
| `04-test-kms-mldsa.sh` | Functional and negative tests (tampering, size limits, EXTERNAL_MU, offline OpenSSL >= 3.5) |

They are packaged as a gzip'ed tar (base64) inside the template to stay under the 51,200-byte limit for
direct template upload, and extracted by `cfn-init`.

## What gets created
| Resource | Purpose |
|---|---|
| 2 KMS keys + aliases | ML-DSA (65 by default) and ECDSA P-256 baseline |
| IAM managed policy + role + instance profile | `Sign`, `Verify`, `GetPublicKey`, `DescribeKey` on the 2 keys only; SSM access; cfn-init/signal on this stack only |
| VPC, public subnet, IGW, route | Outbound only |
| Security group | **No inbound rule**; egress 80/443 only |
| Launch template | Enforces IMDSv2 |
| EC2 instance (AL2023, gp3 16 GB encrypted) | Builds and runs the demo at first boot |

## Deploy
```bash
aws cloudformation deploy \
  --region eu-west-3 \
  --stack-name kms-mldsa-demo \
  --template-file template.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides MlDsaKeySpec=ML_DSA_65 Iterations=300 Warmup=30
```
The stack waits (up to 30 min, usually ~5) for the instance to finish: `CREATE_COMPLETE` means the demo
has run. A setup failure (JDK/Maven download, build) makes the stack fail and roll back; to keep the
instance for debugging use `aws cloudformation create-stack ... --on-failure DO_NOTHING`.

## Check that the installation is finished
The stack waits for the instance signal, so `CREATE_COMPLETE` means setup and demo are done.
```bash
export AWS_REGION=eu-west-3
aws cloudformation describe-stacks --region $AWS_REGION --stack-name kms-mldsa-demo \
  --query "Stacks[0].StackStatus" --output text
# CREATE_IN_PROGRESS = still running (~5 min, 30 max); CREATE_COMPLETE = done;
# ROLLBACK_* / CREATE_FAILED = failed (see ResourceStatusReason, "setup rc=1"):
aws cloudformation describe-stack-events --region $AWS_REGION --stack-name kms-mldsa-demo \
  --query "StackEvents[?LogicalResourceId=='DemoInstance'].[Timestamp,ResourceStatus,ResourceStatusReason]" \
  --output table
```

## Read the results (no SSH needed)
First, populate the instance ID automatically from the stack:
```bash
export AWS_REGION=eu-west-3
INSTANCE_ID=$(aws cloudformation describe-stack-resource --region $AWS_REGION \
  --stack-name kms-mldsa-demo --logical-resource-id DemoInstance \
  --query StackResourceDetail.PhysicalResourceId --output text)
echo $INSTANCE_ID    # should print i-0123456789abcdef0
```

**Option A - interactive shell** (Session Manager plugin required):
```bash
aws ssm start-session --region $AWS_REGION --target $INSTANCE_ID
# then, on the instance:
ls /var/log/kms-mldsa-demo.done        # present = finished (success or not)
tail -f /var/log/kms-mldsa-userdata.log
cat /var/log/kms-mldsa-demo.log        # demo results ("demo exit code: 0" / "ALL CHECKS PASSED")
```

**Option B - read the log without opening a session:**
```bash
CMD_ID=$(aws ssm send-command --region $AWS_REGION --instance-ids $INSTANCE_ID \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["cat /var/log/kms-mldsa-demo.log"]' \
  --query Command.CommandId --output text)
sleep 5
aws ssm get-command-invocation --region $AWS_REGION --command-id $CMD_ID \
  --instance-id $INSTANCE_ID --query StandardOutputContent --output text
```

**Option C - follow progress from the EC2 console log** (may lag by a few minutes):
```bash
aws ec2 get-console-output --region $AWS_REGION --instance-id $INSTANCE_ID --latest --output text | tail -40
```

Notes: if `INSTANCE_ID` is empty, check the stack name and Region. If `start-session` fails right after
deployment, the SSM agent is not registered yet: wait 1-2 minutes and retry.
Re-run the demo on the instance at any time: `sudo /opt/kms-mldsa-demo/run-demo.sh`.

## Clean up
```bash
aws cloudformation delete-stack --stack-name kms-mldsa-demo --region eu-west-3
```
KMS keys enter their waiting period (`KeyDeletionWindowDays`, 7 days minimum) and remain billable until
deleted. Check AWS KMS pricing for asymmetric keys and requests.

## Reading the results
- ML-DSA **signatures and public keys are much larger** than ECDSA (ML-DSA-65: 3,309 B signature,
  1,952 B public key): relevant for JWTs, certificates and size-constrained protocols.
- KMS latency is mostly network + HSM time; compare p50 **and** p95/p99. The instance runs in the same
  Region as KMS, so network time is minimal.
- Local verify shows the cost relying parties pay offline.
- RAW messages are limited to 4,096 bytes; larger payloads need `EXTERNAL_MU`.

## Caveats
- Covers **signatures** (authenticity), not PQ key exchange (hybrid ML-KEM TLS): they are complementary.
- The key policy delegates to IAM for the account root: fine for a throwaway demo, not for production.
- The instance downloads Corretto 25 (AL2023 repos), Maven 3.9.9 (archive.apache.org) and the Maven
  dependencies (Maven Central) at boot, hence the outbound internet access.
- `src/`, `pom.xml` and `ec2-scripts/` are the sources; `template.yaml` embeds copies of them.
  After editing any of them, run `python3 build-template.py` to regenerate the template.
- `aws.sdk.version` in `pom.xml` must be recent enough to know `ML_DSA_SHAKE_256` / `EXTERNAL_MU`.

## 📄 Sources:
-▪️NIST FIPS 203: https://lnkd.in/eXQErqSS
-▪️NIST FIPS 204: https://lnkd.in/ep6eTKgE
-▪️AWS PQC: https://lnkd.in/evfw8X8y
-▪️KMS ML-DSA: https://lnkd.in/erN8X2Dk
-▪️KMS Encapsulate: https://lnkd.in/eQXfBXwv
-▪️S3 PQ-TLS: https://lnkd.in/eSfFpGAu
