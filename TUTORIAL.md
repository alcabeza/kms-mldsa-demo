# Step-by-step tutorial: testing AWS KMS ML-DSA from the EC2 instance

Goal: once the stack is deployed, check from the instance that the installation is complete, that KMS ML-DSA
is deployed and usable, and then measure its performance against ECDSA P-256.

Duration: about 20 minutes (5 minutes of checks, the rest for the benchmark).

> The scripts are already on the instance, in `/opt/kms-mldsa-demo/scripts/`. They are installed by the
> CloudFormation template: there is nothing to copy or install.

---

## Step 0 - Prerequisites (on your workstation)

- AWS CLI v2 configured, with the **Session Manager** plugin installed.
- Stack deployed and in `CREATE_COMPLETE` state:

```bash
export AWS_REGION=eu-west-3
aws cloudformation describe-stacks --region $AWS_REGION --stack-name kms-mldsa-demo \
  --query "Stacks[0].StackStatus" --output text
```

If the status is `CREATE_IN_PROGRESS`, wait: the stack only reaches `CREATE_COMPLETE` after the installation
has finished and the demo has run once (about 5 minutes).

## Step 1 - Open a session on the instance

Populate the instance ID automatically, then open the session:

```bash
export AWS_REGION=eu-west-3
INSTANCE_ID=$(aws cloudformation describe-stack-resource --region $AWS_REGION \
  --stack-name kms-mldsa-demo --logical-resource-id DemoInstance \
  --query StackResourceDetail.PhysicalResourceId --output text)
echo $INSTANCE_ID        # should print i-0123456789abcdef0

aws ssm start-session --region $AWS_REGION --target $INSTANCE_ID
```

If the session fails right after deployment, the SSM agent is not registered yet: wait one or two minutes and
retry.

Inside the session, go to the scripts directory:

```bash
cd /opt/kms-mldsa-demo/scripts
ls -l
```

You should see four executable files: `01-verify-install.sh`, `02-verify-kms-deployment.sh`,
`03-benchmark-kms-mldsa.sh`, `04-test-kms-mldsa.sh`.

> Each script re-runs itself with `sudo` when needed. Run them with `bash <script>`.

## Step 2 - Check that the installation is complete (script 01)

```bash
bash 01-verify-install.sh
```

What the script checks: instance metadata (IMDSv2 enabled, IMDSv1 refused), clock synchronization, cloud-init
and the boot log, JDK 25, Maven, files written by `cfn-init`, compilation, downloaded dependencies, the result of
the first demo run, network access and role credentials.

**Expected result**: `INSTALLATION COMPLETE`, exit code 0.

| If you see | Likely cause | Action |
|---|---|---|
| `Completion marker present` fails | Installation still running | Follow `tail -f /var/log/kms-mldsa-userdata.log`, then re-run |
| `JDK 25 installed` or `Maven installed` fails | Download failed (outbound access) | Read `/var/log/kms-mldsa-userdata.log` |
| `KmsMlDsaDemo compiled` fails | Maven build error | `cat /var/log/kms-mldsa-userdata.log` (look for `BUILD FAILURE`) |
| `Reachable: ... maven` fails | No internet access | Check the route table and the security group |
| `Instance role credentials work` fails | Missing role or instance profile | Check the `InstanceProfile` resource of the stack |
| `Clock is NTP-synchronized` warns | Clock not synchronized | `sudo systemctl status chronyd` |

A warning (`WARN`) is not blocking. A failure (`FAIL`) is.

## Step 3 - Check that KMS ML-DSA is deployed (script 02)

```bash
bash 02-verify-kms-deployment.sh
```

What the script checks:
- the identity in use (the instance role);
- the **ML-DSA** key and the **ECDSA P-256** baseline key: key spec, `SIGN_VERIFY` usage, `Enabled` state,
  customer managed key, key material generated in KMS, advertised signing algorithm;
- a quick `Sign`, `Verify` and `GetPublicKey` smoke test on each key;
- **least privilege**: `kms:ListKeys` and `kms:GetKeyRotationStatus` must be denied;
- reachability of the KMS endpoint.

**Expected result**: `KMS ML-DSA DEPLOYMENT OK`.

| If you see | Likely cause | Action |
|---|---|---|
| `DescribeKey` fails (`AccessDenied`) | The role policy does not cover the key | Check the `DemoPolicyArn` output and the role policy |
| Unexpected `KeySpec` | Wrong key ID in `demo.env` | `cat /opt/kms-mldsa-demo/demo.env` |
| `Sign` fails with an algorithm error | AWS CLI too old for ML-DSA | `aws --version`, update the CLI |
| `kms:ListKeys is denied` warns | The role is broader than intended | Review the policies attached to the role |

## Step 4 - Run the functional and negative tests (script 04)

```bash
bash 04-test-kms-mldsa.sh
```

The script reads the key ID and the Region from `demo.env`. It checks:
- the key configuration and the signature size (2,420, 3,309 or 4,627 bytes depending on the key spec);
- `Sign` and `Verify` in `RAW` mode;
- the cases that must fail: tampered message, corrupted signature, classical algorithm on an ML-DSA key, `RAW`
  message larger than 4,096 bytes, `EXTERNAL_MU` with a size other than 64 bytes;
- the public key (size consistent with the key spec).

**Expected result**: `ALL TESTS PASSED`.

> **One skipped test (`SKIP`) is normal here.** The last part (offline verification with OpenSSL and
> `EXTERNAL_MU` computation) needs OpenSSL 3.5 or later, while Amazon Linux 2023 ships OpenSSL 3.0.
> To cover it, run the same script from a workstation with OpenSSL 3.5+:
> `AWS_REGION=eu-west-3 STACK_NAME=kms-mldsa-demo bash 04-test-kms-mldsa.sh`
> (it reads the key ID from the stack outputs; you need `cloudformation:DescribeStacks`, `kms:Sign`,
> `kms:Verify`, `kms:GetPublicKey` and `kms:DescribeKey`).

## Step 5 - Read the Java demo results again

The Java demo ran automatically at first boot. Read its log again:

```bash
cat /var/log/kms-mldsa-demo.log
```

It contains: the keys, the signature and its verification (KMS and offline with the JDK), the tampered-message
tests, `EXTERNAL_MU`, the ML-DSA / ECDSA size comparison and a first latency table. The last line must be
`demo exit code: 0`, preceded by `ALL CHECKS PASSED`.

To run it again on demand: `sudo /opt/kms-mldsa-demo/run-demo.sh`.

## Step 6 - Measure performance (script 03)

Default run (3 runs of 300 iterations, about 5 to 10 minutes):

```bash
bash 03-benchmark-kms-mldsa.sh
```

Variants:

```bash
RUNS=5 ITERATIONS=500 WARMUP=50 bash 03-benchmark-kms-mldsa.sh   # more precision
RUNS=1 ITERATIONS=100 WARMUP=10 bash 03-benchmark-kms-mldsa.sh   # quick test
```

The script produces six blocks:
1. **Environment**: instance, Availability Zone, Java version.
2. **KMS endpoint probe**: cost of a new connection (TCP connect and TLS handshake, median).
3. **Java runs**: one results file per run.
4. **Latency per operation** (mean, p50, p95, p99, max): KMS Sign, KMS Verify and local verification, for ML-DSA
   and ECDSA P-256.
5. **Stability**: p50 of each run, to spot an atypical run.
6. **ML-DSA vs ECDSA comparison**: ratios on p50 and p95.

### How to read the result

- Look at **p50 and p95/p99**, not only the mean: extreme values often come from the network.
- KMS latency is dominated by the network and by processing on the HSM side. A ratio close to 1 means the change
  of algorithm is barely visible in KMS latency.
- **Local verification** shows the cost paid by a third party that verifies the signature outside KMS.
- If the p50 values of different runs diverge strongly (block 5), re-run with more iterations or at a quieter time.
- The signature and public key sizes (much larger with ML-DSA) are printed in `run-1.log` (`Size comparison`
  line).

### Where the files are

The script prints the output directory (`/var/tmp/kms-mldsa-perf-<date>/`): `summary.txt`, `results-all.csv`,
`results-run*.csv`, `run-*.log`, `probe.txt`.

### Get the results on your workstation

The summary (small) can be retrieved without opening a session, from your workstation. First define a small
function that runs a command on the instance and prints its output:

```bash
ssm_run() {
  local id
  id=$(aws ssm send-command --region $AWS_REGION --instance-ids $INSTANCE_ID \
    --document-name AWS-RunShellScript --parameters "commands=[\"$1\"]" \
    --query Command.CommandId --output text)
  sleep 5
  aws ssm get-command-invocation --region $AWS_REGION --command-id $id \
    --instance-id $INSTANCE_ID --query StandardOutputContent --output text
}

# Print the summary of the latest benchmark
ssm_run 'cat $(ls -d /var/tmp/kms-mldsa-perf-* | tail -1)/summary.txt'
```

The raw CSV files are too large for this method (the output is limited to about 24,000 characters). From the
session, compress them and copy the printed text:

```bash
gzip -c $(ls -d /var/tmp/kms-mldsa-perf-* | tail -1)/results-all.csv | base64 -w0; echo
```

Then on your workstation: `echo '<copied text>' | base64 -d | gunzip > results-all.csv`.

## Step 7 - Summary table

| Step | Script | Success if |
|---|---|---|
| 2 | `01-verify-install.sh` | `INSTALLATION COMPLETE` |
| 3 | `02-verify-kms-deployment.sh` | `KMS ML-DSA DEPLOYMENT OK` |
| 4 | `04-test-kms-mldsa.sh` | `ALL TESTS PASSED` (1 expected `SKIP` on OpenSSL 3.0) |
| 5 | Java demo log | `ALL CHECKS PASSED` and `demo exit code: 0` |
| 6 | `03-benchmark-kms-mldsa.sh` | latency tables for ML-DSA and ECDSA, no failed run |

## Step 8 - Exit and clean up

Leave the session with `exit`. When you are done, delete the stack from your workstation:

```bash
aws cloudformation delete-stack --region $AWS_REGION --stack-name kms-mldsa-demo
```

The KMS keys enter their waiting period (7 days minimum) and remain billable until they are permanently deleted.
The instance, the network and the roles are deleted immediately.

---

## Quick troubleshooting

- **`bash: <script>: No such file`**: you are not in `/opt/kms-mldsa-demo/scripts`.
- **The scripts do not exist**: the template is not the latest version, or `cfn-init` failed. Read
  `/var/log/kms-mldsa-userdata.log` and `/var/log/cfn-init.log`.
- **`mvn` fails during the benchmark**: look at `run-<n>.log` in the output directory.
- **Very irregular latencies**: repeat the test with more iterations. KMS request throttling can also lengthen the
  p99 values; it shows up in the SDK logs.
- **Changing the ML-DSA parameter set** (`ML_DSA_44` or `ML_DSA_87`): the key spec cannot be changed on an
  existing key. Delete the stack and redeploy with `--parameter-overrides MlDsaKeySpec=ML_DSA_87`.
