# Commons Security – Developer Guide

- Project: commons-security
- Maintainer: Avec112
- Last updated: 2025-10-22 08:30 (local)

This document captures project-specific notes to speed up development, testing, and debugging.

## 1. Build and configuration

### Toolchain
- Java: API level set via `maven.compiler.release=11` (builds and runs on JDK 11+). CI uses JDK 21 but the bytecode targets Java 11 APIs.
- Maven: requires Maven >= 3.6.3 (enforced by maven-enforcer-plugin). Recommended: 3.9.x or newer.

### Command basics
- Clean build + run tests: `mvn -B clean verify`
- Build only (skip tests): `mvn -B -DskipTests=true clean package`
- Generate coverage (JaCoCo): `mvn -B verify jacoco:report`
  - Coverage report HTML: `target/site/jacoco/index.html`

### Providers / crypto configuration
- BouncyCastle is added at JVM startup via `BouncyCastleProviderInitializer`, inserted at position 1. Most crypto utils extend this initializer (AesUtils, DigestUtils, RsaCipher, SignatureUtils, KeyUtils), so tests and library calls automatically have BC registered.
- If you instantiate crypto classes before static init (uncommon), ensure class loading triggers the initializer or explicitly add the provider in test bootstrap.

### Notable plugins
- maven-compiler-plugin: `release=11`
- maven-enforcer-plugin: guards Maven/Java versions
- jacoco-maven-plugin: prepare-agent + report at `verify`
- maven-source-plugin: attaches sources
- maven-javadoc-plugin + maven-gpg-plugin: configured but skipped for local builds (`skip=true`)
- versions-maven-plugin: rules from `.maven-version-rules.xml` (keeps dependencies sensible)
- org.sonatype.central: publishing plugin (not relevant for local dev)

## 2. Testing information

### Frameworks
- JUnit Jupiter 6 (`org.junit.jupiter:junit-jupiter:6.0.0`)
- AssertJ for fluent assertions
- Mockito (inline) available if mocking is needed

### Running tests
- All tests: `mvn -B test` or `mvn -B verify`
- Single class: `mvn -Dtest=com.github.avec112.security.crypto.CryptoUtilsFacadeTest test`
- Pattern/Multiple: `mvn -Dtest="Aes*Test,**/rsa/*Test" test`
- Single method: `mvn -Dtest=com.github.avec112.security.crypto.CryptoUtilsFacadeTest#aesEncryptAndDecrypt test`
- Fail-fast: `mvn -Dsurefire.failIfNoSpecifiedTests=false -Dtest=... test`

### Coverage
- After `mvn verify jacoco:report` open `target/site/jacoco/index.html`
- XML at `target/site/jacoco/jacoco.xml` (used by CI/Coveralls)

### Test data and environment specifics
- Crypto operations use random IVs/salts; ciphertext differs between runs. Prefer round-trip assertions (encrypt → decrypt → equals) rather than comparing raw ciphertext.
- Some APIs expose value objects (`PlainText`, `CipherText`, `Password`) backed by Lombok `@Value`. Accessors are `getValue()`.
- RSA operations and signatures rely on BouncyCastle being registered (auto via superclass). If you create standalone tests not touching those classes, you can extend `BouncyCastleProviderInitializer` to force provider registration in `@BeforeAll` context.

### Adding a new test (example validated locally)
- Create file: `src/test/java/com/github/avec112/security/examples/QuickStartTest.java`
- Example content:

```java
package com.github.avec112.security.examples;

import com.github.avec112.security.crypto.CryptoUtils;
import com.github.avec112.security.crypto.domain.CipherText;
import com.github.avec112.security.crypto.domain.Password;
import com.github.avec112.security.crypto.domain.PlainText;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class QuickStartTest {
    @Test
    void aes_encrypt_then_decrypt_roundtrip() throws Exception {
        PlainText input = new PlainText("Hello, commons-security!");
        Password password = new Password("S3cr3t-P@ssw0rd");

        CipherText cipherText = CryptoUtils.aesEncrypt(input, password);
        PlainText decrypted = CryptoUtils.aesDecrypt(cipherText, password);

        assertThat(decrypted.getValue()).isEqualTo(input.getValue());
    }
}
```

- Run only this test: `mvn -Dtest=com.github.avec112.security.examples.QuickStartTest test`
- Run a single method: `mvn -Dtest=com.github.avec112.security.examples.QuickStartTest#aes_encrypt_then_decrypt_roundtrip test`
- Note: We executed this example successfully during the preparation of this guide, then removed the file to keep the repo unchanged.

## 3. Additional development and debugging notes

### API structure and patterns
- `CryptoUtils` is a facade wrapping common flows (AES, RSA, hybrid, Shamir, digest, signature). For finer control use underlying types (`AesEncryptor`/`AesDecryptor`, `RsaCipher`, `Shamir`, `SignatureUtils`, `DigestUtils`).
- Domain wrappers (`PlainText`, `CipherText`, `Password`) improve type-safety; use `getValue()` to access underlying String.

### Determinism & reproducibility
- AES (CTR/GCM) encryption is intentionally non-deterministic due to random IV/salt. Do not assert fixed ciphertext; verify decryption yields original `PlainText` or use provided digest/signature utilities when you need reproducible comparisons.
- Key generation, Shamir share splitting, and signatures also use `SecureRandom`; tests should assert structural properties, sizes, or successful round-trips.

### Provider placement
- The project inserts BouncyCastle at provider index 1. If your environment registers other providers (e.g., FIPS), verify ordering or adapt tests accordingly. Fail-fast check throws if BC cannot be registered.

### Exceptions
- `BadCipherConfigurationException` and `BadCipherTextException` differentiate config vs. ciphertext errors in AES flows; catch accordingly in tests.

### Coding style
- Java 11 features are acceptable. Project uses Lombok (`@Value`) and AssertJ. Prefer final/immutability for data types.
- Keep methods small and focused. Favor descriptive test names (`methodName_state_expectedBehavior`) and parameterized tests when appropriate.

### CI specifics (GitHub Actions)
- Workflow: `.github/workflows/maven.yml`
  - JDK 21 (Adopt). Cache: maven.
  - Command: `mvn -B clean verify jacoco:report`
  - Artifacts: uploads `target/site/jacoco/`
  - Coveralls upload on master branch.
  - Builds README.pdf from README.adoc using Asciidoctor and deploys to GitHub Pages on master.
- Local dev is not required to generate PDF; that’s CI-only. If you need it locally, install Ruby 3.2+, `gem install asciidoctor-pdf rouge`, then run the `asciidoctor-pdf` command shown in the workflow.

## 4. Quick troubleshooting
- “No tests were found” when using `-Dtest` filters: ensure the filter matches the fully qualified class or method and that Surefire has tests on the classpath (use `test` phase, not `package`).
- Provider registration issues: ensure your test touches a class extending `BouncyCastleProviderInitializer` or import and extend that class directly in your test.
- Java version mismatches: despite building with `release=11`, ensure your local JDK is 11+ (JDK 8 will fail the enforcer).

## 5. Useful commands (recap)
- `mvn -B clean verify`
- `mvn -Dtest=com.github.avec112.security.crypto.CryptoUtilsFacadeTest test`
- `mvn -Dtest=com.github.avec112.security.crypto.CryptoUtilsFacadeTest#aesEncryptAndDecrypt test`
- `mvn verify jacoco:report && start target/site/jacoco/index.html`  # Windows: open coverage in default browser

---

Note on repo hygiene for examples: We intentionally remove temporary example tests created to validate this guide. Keep long-lived examples under a dedicated package (e.g., `...examples`) only if they provide enduring value.
