# commons-security-demo

> Command-line demo application for [commons-security](https://github.com/avec112/commons-security)

This is a lightweight **CLI showcase** built with [Picocli](https://picocli.info) that demonstrates selected cryptographic features provided by the `commons-security-core` library.

It can be used both as a reference implementation and as a local testing tool for encryption, hashing, and related functionality.

---

## Build

The demo is a separate Maven module under the main `commons-security` project.

To build only the demo (and its dependencies):

```bash
mvn clean package -pl commons-security-demo -am
```

This produces a self-contained **runnable JAR** under:

```
commons-security-demo/target/commons-security-demo-1.0-SNAPSHOT.jar
```

The JAR already includes all dependencies (via Maven Shade).

---

## Run

Run the demo application directly from the command line:

```bash
java -jar commons-security-demo/target/commons-security-demo-1.0-SNAPSHOT.jar [COMMAND] [OPTIONS]
```

### Example

Encrypt a simple text using AES-GCM:

```bash
java -jar commons-security-demo/target/commons-security-demo-1.0-SNAPSHOT.jar aes --text "A message" --password "Password123"
```

Example output:

```
Encrypted (Base64): hDltHRPoiksSOecpYo7T3jW7nRLAqPtuDSJREb/4bwrxOODHDtSr/oaX2e9jMl+ZCN8cucsp
```

---

## Commands

| Command | Description |
|----------|-------------|
| `aes` | Encrypts text using AES-GCM with a PBKDF2-derived key. |
| *(more commands will be added later)* | |

To view all commands:

```bash
java -jar commons-security-demo-1.0-SNAPSHOT.jar --help
```

Or help for a specific command:

```bash
java -jar commons-security-demo-1.0-SNAPSHOT.jar aes --help
```

---

## 🧰 Technology stack

- **Java 11+**
- **Maven 3.6.3+**
- **Picocli 4.7.x**
- **commons-security-core** (internal module)

---

## 🧾 Notes

- This demo JAR is **not published** to Maven Central — it is for local use only.
- It is shaded with all dependencies and can run **offline**.
- More commands will be added incrementally to demonstrate additional features like RSA, message digests, and Shamir’s Secret Sharing.
- See commons-security documentation [here (github)](https://github.com/avec112/commons-security/) or [here (pdf)](https://avec112.github.io/commons-security/README.pdf)

---

## 📄 License

This project follows the same license as `commons-security-core`.

---

© 2025 Avec112
