package demo;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.KmsInvalidSignatureException;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Demo: post-quantum digital signatures with AWS KMS (ML-DSA, FIPS 204).
 *
 * 1. Checks the KMS key (key spec, signing algorithm).
 * 2. Signs with ML_DSA_SHAKE_256 (RAW), verifies in KMS and locally with the JDK (offline).
 * 3. Checks that a tampered message is rejected.
 * 4. Signs with EXTERNAL_MU (mu computed client side) and verifies the result.
 * 5. Measures latency (KMS Sign, KMS Verify, local Verify): ML-DSA vs ECDSA P-256 baseline.
 *
 * Env vars: ML_DSA_KEY_ID (required), ECDSA_KEY_ID (optional baseline),
 *           ITERATIONS (default 200), WARMUP (default 20). Region/credentials: default AWS chain.
 */
public final class KmsMlDsaDemo {

    private interface Op { void run() throws Exception; }

    private record Target(String label, String keyId, SigningAlgorithmSpec alg,
                          String keyFactoryAlg, String sigAlg, PublicKey pub, byte[] spki) {}

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        String mlKeyId = requireEnv("ML_DSA_KEY_ID");
        String ecKeyId = System.getenv("ECDSA_KEY_ID");
        int iterations = intEnv("ITERATIONS", 200);
        int warmup = intEnv("WARMUP", 20);

        byte[] message = new byte[256];
        new SecureRandom().nextBytes(message);

        try (KmsClient kms = KmsClient.create()) {
            System.out.println("== 1. Keys ==");
            Target ml = load(kms, "ML-DSA", mlKeyId, SigningAlgorithmSpec.ML_DSA_SHAKE_256, "ML-DSA", "ML-DSA");
            Target ec = (ecKeyId == null || ecKeyId.isBlank()) ? null
                    : load(kms, "ECDSA-P256", ecKeyId, SigningAlgorithmSpec.ECDSA_SHA_256, "EC", "SHA256withECDSA");

            System.out.println("\n== 2. Sign (RAW) / verify in KMS and offline with the JDK ==");
            byte[] sig = kmsSign(kms, ml, message);
            System.out.printf("signature: %d bytes, public key (SPKI): %d bytes%n", sig.length, ml.spki().length);
            check("KMS Verify accepts the signature", kmsVerify(kms, ml, message, sig));
            check("Local (JDK) verify accepts the signature", localVerify(ml, message, sig));

            System.out.println("\n== 3. Tampered message must be rejected ==");
            byte[] tampered = message.clone();
            tampered[0] ^= 0x01;
            check("KMS Verify rejects tampered message", !kmsVerify(kms, ml, tampered, sig));
            check("Local verify rejects tampered message", !localVerify(ml, tampered, sig));

            System.out.println("\n== 4. EXTERNAL_MU (mu computed outside KMS) ==");
            byte[] mu = externalMu(ml.spki(), message);
            byte[] sigMu = kms.sign(r -> r.keyId(ml.keyId())
                            .message(SdkBytes.fromByteArray(mu))
                            .messageType(MessageType.EXTERNAL_MU)
                            .signingAlgorithm(ml.alg()))
                    .signature().asByteArray();
            check("EXTERNAL_MU signature verifies locally against the original message",
                    localVerify(ml, message, sigMu));
            System.out.println("info: EXTERNAL_MU signature identical to RAW signature: " + Arrays.equals(sig, sigMu));

            if (ec != null) {
                byte[] ecSig = kmsSign(kms, ec, message);
                System.out.printf("%nSize comparison: ML-DSA signature %d B vs ECDSA %d B; public key %d B vs %d B%n",
                        sig.length, ecSig.length, ml.spki().length, ec.spki().length);
            }

            System.out.printf("%n== 5. Latency (n=%d, warmup=%d, message=%d bytes, ms) ==%n",
                    iterations, warmup, message.length);
            List<String> csv = new ArrayList<>();
            csv.add("operation,iteration,ms");
            System.out.printf("%-26s %8s %8s %8s %8s %8s%n", "operation", "mean", "p50", "p95", "p99", "max");

            benchTarget(kms, ml, message, warmup, iterations, csv);
            if (ec != null) {
                benchTarget(kms, ec, message, warmup, iterations, csv);
            }
            Path out = Path.of("results.csv");
            Files.write(out, csv, StandardCharsets.UTF_8);
            System.out.println("\nRaw samples written to " + out.toAbsolutePath());
        }

        System.out.println(failures == 0 ? "\nALL CHECKS PASSED" : "\n" + failures + " CHECK(S) FAILED");
        if (failures != 0) {
            System.exit(1);
        }
    }

    // ---------- KMS / crypto helpers ----------

    private static Target load(KmsClient kms, String label, String keyId, SigningAlgorithmSpec alg,
                               String keyFactoryAlg, String sigAlg) throws GeneralSecurityException {
        KeyMetadata md = kms.describeKey(r -> r.keyId(keyId)).keyMetadata();
        System.out.printf("%s: keySpec=%s, usage=%s, signingAlgorithms=%s%n",
                label, md.keySpecAsString(), md.keyUsageAsString(), md.signingAlgorithmsAsStrings());
        if (!md.signingAlgorithmsAsStrings().contains(alg.toString())) {
            throw new IllegalStateException(label + ": key does not support " + alg);
        }
        byte[] spki = kms.getPublicKey(r -> r.keyId(keyId)).publicKey().asByteArray();
        PublicKey pub = KeyFactory.getInstance(keyFactoryAlg).generatePublic(new X509EncodedKeySpec(spki));
        return new Target(label, keyId, alg, keyFactoryAlg, sigAlg, pub, spki);
    }

    private static byte[] kmsSign(KmsClient kms, Target t, byte[] msg) {
        return kms.sign(r -> r.keyId(t.keyId())
                        .message(SdkBytes.fromByteArray(msg))
                        .messageType(MessageType.RAW)
                        .signingAlgorithm(t.alg()))
                .signature().asByteArray();
    }

    private static boolean kmsVerify(KmsClient kms, Target t, byte[] msg, byte[] sig) {
        try {
            return kms.verify(r -> r.keyId(t.keyId())
                            .message(SdkBytes.fromByteArray(msg))
                            .messageType(MessageType.RAW)
                            .signingAlgorithm(t.alg())
                            .signature(SdkBytes.fromByteArray(sig)))
                    .signatureValid();
        } catch (KmsInvalidSignatureException e) {
            return false; // KMS signals an invalid signature with an exception
        }
    }

    private static boolean localVerify(Target t, byte[] msg, byte[] sig) throws GeneralSecurityException {
        Signature v = Signature.getInstance(t.sigAlg());
        v.initVerify(t.pub());
        v.update(msg);
        try {
            return v.verify(sig);
        } catch (SignatureException e) {
            return false;
        }
    }

    /**
     * External mu, FIPS 204 section 6.2 (pure ML-DSA, empty context):
     * tr = SHAKE256(pk, 64); mu = SHAKE256(tr || 0x00 || 0x00 || M, 64).
     */
    private static byte[] externalMu(byte[] spki, byte[] msg) {
        byte[] rawPk = SubjectPublicKeyInfo.getInstance(spki).getPublicKeyData().getBytes();
        byte[] tr = shake256(rawPk, 64);
        SHAKEDigest d = new SHAKEDigest(256);
        d.update(tr, 0, tr.length);
        d.update((byte) 0x00); // domain separator: pure ML-DSA
        d.update((byte) 0x00); // context length = 0
        d.update(msg, 0, msg.length);
        byte[] mu = new byte[64];
        d.doFinal(mu, 0, mu.length);
        return mu;
    }

    private static byte[] shake256(byte[] in, int outLen) {
        SHAKEDigest d = new SHAKEDigest(256);
        d.update(in, 0, in.length);
        byte[] out = new byte[outLen];
        d.doFinal(out, 0, outLen);
        return out;
    }

    // ---------- benchmark ----------

    private static void benchTarget(KmsClient kms, Target t, byte[] msg, int warmup, int n, List<String> csv)
            throws Exception {
        byte[] sig = kmsSign(kms, t, msg);
        bench(t.label() + " KMS Sign", warmup, n, () -> kmsSign(kms, t, msg), csv);
        bench(t.label() + " KMS Verify", warmup, n, () -> kmsVerify(kms, t, msg, sig), csv);
        bench(t.label() + " local Verify", warmup, n, () -> localVerify(t, msg, sig), csv);
    }

    private static void bench(String label, int warmup, int n, Op op, List<String> csv) throws Exception {
        for (int i = 0; i < warmup; i++) {
            op.run();
        }
        double[] ms = new double[n];
        for (int i = 0; i < n; i++) {
            long t0 = System.nanoTime();
            op.run();
            ms[i] = (System.nanoTime() - t0) / 1_000_000.0;
            csv.add(label + "," + i + "," + String.format(java.util.Locale.ROOT, "%.3f", ms[i]));
        }
        double[] sorted = ms.clone();
        Arrays.sort(sorted);
        double mean = Arrays.stream(ms).average().orElse(Double.NaN);
        System.out.printf(java.util.Locale.ROOT, "%-26s %8.2f %8.2f %8.2f %8.2f %8.2f%n",
                label, mean, pct(sorted, 50), pct(sorted, 95), pct(sorted, 99), sorted[n - 1]);
    }

    /** Nearest-rank percentile on a sorted array. */
    private static double pct(double[] sorted, double p) {
        int idx = (int) Math.ceil(p / 100.0 * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, idx))];
    }

    // ---------- misc ----------

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        if (!ok) {
            failures++;
        }
    }

    private static String requireEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            throw new IllegalStateException("Missing environment variable " + name);
        }
        return v;
    }

    private static int intEnv(String name, int def) {
        String v = System.getenv(name);
        return (v == null || v.isBlank()) ? def : Integer.parseInt(v.trim());
    }
}
