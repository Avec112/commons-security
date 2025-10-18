# ✅ commons-security — Test Coverage & Quality Backlog

This document tracks enhancements and refinements for the test suite across all crypto components  
(**AES**, **RSA**, **Digest**, **Signature**, **Password**, **Shamir**, **CryptoUtils**, **Encoding**).

---

## 🥇 Top Priority — Correctness & Determinism

| ✅ / ☐ | Task | Modules |
|:-----:|------|----------|
|   ✅   | Use `StandardCharsets.UTF_8` explicitly in all `getBytes()` / `new String(byte[])` calls | EncodingUtilsTest, DigestUtilsTest, SignatureUtilsTest, PasswordEncoderUtilsTest, CryptoUtilsTest |
|   ✅   | Add negative AES test: decrypt with wrong password should not equal plaintext | CryptoUtilsTest |
|   ❌   | Add negative RSA test: decrypt with wrong private key should not equal plaintext | CryptoUtilsTest |
|   ✅   | Add password mismatch tests (verify false when password differs) | PasswordEncoderUtilsTest |
|   ✅   | Add signature mismatch tests (wrong key or tampered data) | SignatureUtilsTest |
|   ✅   | Validate Shamir threshold arguments (`threshold > total` or `< 2` should throw) | ShamirTest |
|   ✅   | Add at least one known fixed digest vector (e.g. SHA-256 of “OpenAI”) | DigestUtilsTest |
|   ✅   | Add known fixed signature vector regression test | SignatureUtilsTest |

---

## 🥈 Medium Priority — Completeness & Robustness

| ✅ / ☐ | Task | Modules |
|:--:|------|----------|
| ✅ | Verify all combinations of threshold shares reconstruct correctly (3-of-5) | ShamirTest |
| ☐ | Verify all generated shares are unique | ShamirTest |
| ✅ | Validate prefix format `{ARGON2}`, `{BCRYPT}`, `{SCRYPT}`, `{PBKDF2}` | PasswordEncoderUtilsTest |
| ✅ | Verify Argon2 hash does **not** match when checked with BCrypt/Scrypt encoder | PasswordEncoderUtilsTest |
| ☐ | Compare `CryptoUtils` AES/RSA results with direct `AesEncryptor`/`RsaCipher` results | CryptoUtilsTest |
| ☐ | Add invalid share handling test — ensure exceptions bubble up | CryptoUtilsTest |

---

## 🥉 Low Priority — Polish & Future-Proofing

| ✅ / ☐ | Task | Modules |
|:--:|------|----------|
| ❌ | Use `"BC"` provider explicitly in `MessageDigest` / `Signature.getInstance()` | DigestUtilsTest, SignatureUtilsTest |
| ❌ | Add Argon2 encoding performance sanity check (`@Timeout(2)`) | PasswordEncoderUtilsTest |
| ❌ | Tag large / slow tests (e.g. 100 KB Shamir secret) with `@Tag("slow")` | ShamirTest |
| ☐ | Add share encoding idempotence test (double-encoded ≠ valid) | ShamirTest |
| ☐ | Add RSASSA-PSS placeholder tests for upcoming modernization | SignatureUtilsTest |

---

## 🧱 Structural / Naming Cleanup

| ✅ / ☐ | Task | Modules |
|:--:|------|----------|
| ☐ | Organize tests into feature packages:<br> `encoding/`, `aes/`, `rsa/`, `signature/`, `password/`, `shamir/`, `crypto/` | All |
| ☐ | Rename `CryptoUtilsTest` → `CryptoUtilsIntegrationTest` | crypto |
| ☐ | Use `@TestMethodOrder` **only** when order truly matters (e.g. key generation) | KeyUtilsTest |

---

## 🏁 When complete

✅ 100 % functional & negative-path coverage  
✅ Deterministic, reproducible results across providers  
✅ UTF-8 & provider consistency  
✅ Cross-algorithm isolation and regression protection  
✅ CI-ready, fast, and maintainable structure
