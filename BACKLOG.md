# 🧩 commons-security Backlog

A modernization and quality-improvement plan for the **commons-security** library.  
Goal: complete modernization, testing, and documentation for internal and educational use.

---

## 🔒 Tier 1 – Critical correctness & security fixes
*(Must be completed before any internal or external use)*

- [ ] **Fix Shamir’s Secret hardcoded parameters**
  - Replace `new Scheme(new SecureRandom(), 100, 100)` with dynamic `(n, k)` from input.
  - Add validation: ensure at least `k` shares are provided when joining.

- [ ] **Upgrade RSA to OAEP-SHA256**
  - Use `"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"`.
  - Update `RsaCipher` and `EncryptBuilder` accordingly.

- [ ] **Upgrade signatures to RSASSA-PSS**
  - Use `"SHA256withRSAandMGF1"` (RSASSA-PSS) in `SignatureUtils`.

- [ ] **Fix DigestUtils hex encoding bug**
  - `hexDigest()` currently Base64-encodes output. Replace with `EncodingUtils.hexEncode()`.

---

## ⚙️ Tier 2 – Security robustness & modernization

- [ ] **Use binary entropy for AES keys**
  - Replace `RandomUtils.randomString(20)` with secure random bytes.
  - Encode to Base64 and size by `EncryptionStrength`.

- [ ] **Default AES strength to 256-bit**

- [ ] **Rename builder `optional()` methods**
  - `.optional(EncryptionMode)` → `.withMode(EncryptionMode)`
  - `.optional(EncryptionStrength)` → `.withStrength(EncryptionStrength)`

- [ ] **Reuse single SecureRandom instance**
  - `private static final SecureRandom RNG = SecureRandom.getInstanceStrong();`

- [ ] **Prioritize BouncyCastle provider**
  - Use `Security.insertProviderAt(new BouncyCastleProvider(), 1)`.

---

## 🧱 Tier 3 – API & developer-experience improvements

- [ ] **Add JSON serialization for `HybridEncryptionResult`**
  - Include `toJson()` / `fromJson()` helpers (Gson or Jackson).
  - Add optional `version` field for future compatibility.

- [ ] **Rename `encryptedSymmetricalKey` → `encryptedKey`**

- [ ] **Add `describe()` helper**
  - Return human-readable AES summary, e.g. `"GCM@256-bit"`.

- [ ] **Add digest/signature helpers in `CryptoUtils`**
  - `digest(String data)`
  - `sign(String data, PrivateKey)`
  - `verify(byte[] sig, String data, PublicKey)`

- [ ] **Add hybrid encrypt/decrypt helpers in `CryptoUtils`**
  - `hybridEncrypt(PlainText, PublicKey)`
  - `hybridDecrypt(HybridEncryptionResult, PrivateKey)`

---

## 🧩 Tier 4 – Password encoding improvements

- [ ] **Cache `DelegatingPasswordEncoder` instances**
  - Build once per `PasswordEncoderType`.

- [ ] **Make encoder map unmodifiable**
  - Wrap with `Collections.unmodifiableMap()`.

- [ ] **Add `matchesAuto()` helper**
  - Auto-detect encoder type from `{id}` prefix.

- [ ] **Add `needsUpgrade()` helper**
  - Allow checking if encoded password should be re-hashed with stronger algorithm.

---

## ✍️ Tier 5 – Documentation & cleanup

- [ ] **Update `README.adoc`**
  - Reflect new AES/RSA defaults and PSS signatures.
  - Add section on hybrid encryption.
  - Include a *“Not for production use”* disclaimer.

- [ ] **Add library version metadata**
  - e.g. `public static final String VERSION = "1.0.0";`

- [ ] **Rename minor typos**
  - e.g. `ciperText` → `cipherText`.

- [ ] **Add/extend unit tests**
  - [ ] AES encrypt/decrypt roundtrip
  - [ ] RSA OAEP encrypt/decrypt
  - [ ] Hybrid encrypt/decrypt roundtrip
  - [ ] Signature sign/verify
  - [ ] Shamir split/join
  - [ ] Password encoder encode/match

- [ ] **Tag release as educational/reference**
  - Clarify in README:  
    > “This library is for educational and internal use only.  
    > Not intended for production deployment or active maintenance.”

---

## 🧭 Optional Future Ideas

- [ ] Add ECC support (ECIES, Ed25519, ECDSA)
- [ ] Add BLAKE2b/BLAKE3 digests
- [ ] Add deterministic JSON serialization
- [ ] Add streaming AES-GCM for large files
- [ ] Create Vaadin demo UI for encryption/decryption workflow

---

*commons-security – modernization plan © 2025 Avec112*
