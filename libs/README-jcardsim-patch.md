# Patched jcardsim (test simulator)

`jcardsim-3.0.5-SNAPSHOT.jar` here is the upstream jcardsim from the `jcardsim/`
submodule **with one fix applied**. `build.gradle` points the `testCompile`
dependency at this vendored copy instead of the submodule jar, because the
submodule change is not tracked by this repo (git submodules only track a commit
pointer), so a fresh clone would otherwise get the unpatched jar and fail.

## The fix

`javacard.security.KeyBuilder.buildKey(...)` in the upstream jar does **not**
handle `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` (constant value **31**) — its
switch falls through to `default → CryptoException.NO_SUCH_ALGORITHM`.

The Keycard applet uses that key type (`SECP256k1.<init>` and
`SecureChannelV2`), so the applet cannot even be installed in the simulator:
every test failed at `installApplet` with a swallowed `CryptoException`.

The patch adds the transient EC private-key cases (jcardsim has no real
transient/deselect semantics, so they map to the persistent EC private key):

```java
case 28: // TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET
case 29: // TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT
    key = new ECPrivateKeyImpl(TYPE_EC_F2M_PRIVATE, keyLength);
    break;
case 30: // TYPE_EC_FP_PRIVATE_TRANSIENT_RESET
case 31: // TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT
    key = new ECPrivateKeyImpl(TYPE_EC_FP_PRIVATE, keyLength);
    break;
```

The full patched source is saved as `jcardsim-KeyBuilder.patched.java`.

## How to reproduce the jar

1. Decompile the class from the pristine submodule jar (e.g. with CFR):
   `java -jar cfr.jar jcardsim/jcardsim-3.0.5-SNAPSHOT.jar --jarfilter 'javacard.security.KeyBuilder' --outputdir /tmp/kb`
2. Apply the cases above (or use `jcardsim-KeyBuilder.patched.java`).
3. Compile against the jar + BouncyCastle 1.65:
   `javac -source 8 -target 8 -cp "<jar>:<bcprov-1.65.jar>" -d /tmp/out javacard/security/KeyBuilder.java`
4. Splice into a copy of the jar:
   `cp jcardsim/jcardsim-3.0.5-SNAPSHOT.jar libs/ && (cd /tmp/out && jar uf <repo>/libs/jcardsim-3.0.5-SNAPSHOT.jar javacard/security/KeyBuilder.class)`

## Status

With this patch: `./gradlew test` (simulator target) installs the applet and
**16 / 19 tests pass**. The 3 remaining failures are simulator status-word
quirks unrelated to applet function, deferred for later:
`getDataNdefSegmentationTest`, `getChallengeWithSecureChannelTest`,
`openSecureChannelTest` (negative-path SW mismatch). All core operations —
key generation, signing, key export, secure channel, PIN, Cash — pass.

jcardsim is Apache-2.0 (Copyright Licel LLC); this modified copy remains Apache-2.0.
