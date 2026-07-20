package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.applet.*;
import im.status.keycard.applet.Certificate;
import im.status.keycard.desktop.PCSCCardChannel;
import static im.status.keycard.SecureChannelV2.PUBKEY_SIZE;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import javacard.framework.AID;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.RawTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import static org.apache.commons.codec.digest.DigestUtils.sha256;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import apdu4j.pcsc.TerminalManager;

@DisplayName("Test the Keycard Applet")
public class KeycardTest {
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;
  private static im.status.keycard.io.CardChannel sdkChannel;
  private static CardSimulator simulator;
  private static KeyPair caKeyPair;
  private static Certificate identCert;
  private static KeyPair identKeyPair;

  private TestKeycardCommandSet cmdSet;

  private static final int TARGET_SIMULATOR = 0;
  private static final int TARGET_CARD = 1;

  private static final int TARGET;

  static {
    switch(System.getProperty("im.status.keycard.test.target", "card")) {
      case "simulator":
        TARGET = TARGET_SIMULATOR;
        break;
      case "card":
        TARGET = TARGET_CARD;
        break;
      default:
        throw new RuntimeException("Unknown target");
    }
  }

  @BeforeAll
  static void initAll() throws Exception {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        openSimulatorChannel();
        break;
      case TARGET_CARD:
        openCardChannel();
        break;
      default:
        throw new IllegalStateException("Unknown target");
    }

    // Fixed CA keypair for reproducible tests
    ECParameterSpec caSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
    java.math.BigInteger caPriv = new java.math.BigInteger("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", 16);
    org.bouncycastle.jce.spec.ECPrivateKeySpec caPrivSpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(caPriv, caSpec);
    org.bouncycastle.jce.spec.ECPublicKeySpec caPubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(caSpec.getG().multiply(caPriv), caSpec);
    caKeyPair = new java.security.KeyPair(kf.generatePublic(caPubSpec), kf.generatePrivate(caPrivSpec));

    initIfNeeded();
  }

  private static void initCapabilities(ApplicationInfo info) {
    HashSet<String> capabilities = new HashSet<>();

    if (info.hasSecureChannelCapability()) {
      capabilities.add("secureChannel");
    }

    if (info.hasCredentialsManagementCapability()) {
      capabilities.add("credentialsManagement");
    }

    if (info.hasKeyManagementCapability()) {
      capabilities.add("keyManagement");
    }

    if (info.hasNDEFCapability()) {
      capabilities.add("ndef");
    }

    if (info.hasFactoryResetCapability()) {
      capabilities.add("factoryReset");
    }

    CapabilityCondition.availableCapabilities = capabilities;
  }

  private static void openSimulatorChannel() throws Exception {
    simulator = new CardSimulator();

    // Install KeycardApplet
    AID aid = AIDUtil.create(Identifiers.KEYCARD_AID);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(Identifiers.getKeycardInstanceAID().length);
    bos.write(Identifiers.getKeycardInstanceAID());

    simulator.installApplet(aid, KeycardApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install NDEFApplet
    aid = AIDUtil.create(Identifiers.NDEF_AID);
    bos.write(Identifiers.NDEF_INSTANCE_AID.length);
    bos.write(Identifiers.NDEF_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, NDEFApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install CashApplet
    aid = AIDUtil.create(Identifiers.CASH_AID);
    bos.write(Identifiers.CASH_INSTANCE_AID.length);
    bos.write(Identifiers.CASH_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, CashApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install CashApplet
    aid = AIDUtil.create(Identifiers.IDENT_AID);
    bos.write(Identifiers.IDENT_INSTANCE_AID.length);
    bos.write(Identifiers.IDENT_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, IdentApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();    

    cardTerminal = CardTerminalSimulator.terminal(simulator);

    openPCSCChannel();
  }

  private static void openCardChannel() throws Exception {
    TerminalFactory tf = TerminalManager.getTerminalFactory();

    for (CardTerminal t : tf.terminals().list()) {
      if (t.isCardPresent()) {
        cardTerminal = t;
        break;
      }
    }

    openPCSCChannel();
  }

  private static void openPCSCChannel() throws Exception {
    Card apduCard = cardTerminal.connect("*");
    apduChannel = apduCard.getBasicChannel();
    sdkChannel = new PCSCCardChannel(apduChannel);
  }

  private static void initCard(KeycardCommandSet cmdSet) throws Exception {
    assertEquals(0x9000, cmdSet.init("000000", "024680", "012345678901", new byte[0], (byte) 3, (byte) 5).getSw());
    cmdSet.select().checkOK();
  }

  private static void initIfNeeded() throws Exception {
    // Generate the DAK identity keypair/certificate only once per JVM run (not once per test).
    // Certificate.createCertificate() signs with a random ECDSA nonce; the DER r/s components
    // occasionally serialize shorter than 32 bytes (client SDK's toUInt() only strips a single
    // leading zero byte and does not re-pad), which makes storeData() below fail with SW_WRONG_DATA.
    // Reusing one fixed, already-known-good Certificate object across every @BeforeEach call keeps
    // the (tiny, pre-existing) odds of hitting that edge case the same as before per-test isolation
    // was introduced, instead of multiplying them by the number of tests.
    if (identCert == null) {
      identKeyPair = Certificate.generateIdentKeyPair();
      identCert = Certificate.createCertificate(caKeyPair, identKeyPair);
    }
    IdentCommandSet idCmdSet = new IdentCommandSet(sdkChannel);
    idCmdSet.select().checkOK();
    idCmdSet.storeData(identCert.toStoreData()).checkOK();

    KeycardCommandSet cmdSet = new KeycardCommandSet(sdkChannel, ((org.bouncycastle.jce.interfaces.ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true));
    cmdSet.select().checkOK();

    initCapabilities(cmdSet.getApplicationInfo());

    if (!cmdSet.getApplicationInfo().isInitializedCard()) {
      initCard(cmdSet);
      initCapabilities(cmdSet.getApplicationInfo());
    }
  }

  @BeforeEach
  void init() throws Exception {
    if (TARGET == TARGET_SIMULATOR) {
      openSimulatorChannel(); // fresh CardSimulator + reinstall all applets (pristine persistent state)
      initIfNeeded();         // reprovision the DAK cert + init the card (PIN/PUK)
    } else {
      reset();
    }
    cmdSet = new TestKeycardCommandSet(sdkChannel, ((org.bouncycastle.jce.interfaces.ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true));
    cmdSet.select().checkOK();
  }

  @AfterEach
  void tearDown() throws Exception {
    resetAndSelectAndOpenSC();

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      APDUResponse response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }
  }

  @Test
  @DisplayName("SELECT command")
  void selectTest() throws Exception {
    APDUResponse response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    byte[] data = response.getData();
    assertTrue(new ApplicationInfo(data).isInitializedCard());
  }

  @Test
  @DisplayName("OPEN SECURE CHANNEL command")
  @Capabilities("secureChannel")
  void openSecureChannelTest() throws Exception {
    APDUResponse response;

    // ----- Bad/edge case: wrong data length -----
    // Too short (only salt, no public key)
    byte[] salt = new byte[32];
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, salt));
    assertEquals(0x6A80, response.getSw());

    // Too long (salt + public key + extra byte)
    byte[] clientPubKey = new byte[65];
    clientPubKey[0] = 0x04;
    for (int i = 1; i < clientPubKey.length; i++) {
      clientPubKey[i] = (byte) i;
    }
    byte[] tooLongData = new byte[98];
    System.arraycopy(salt, 0, tooLongData, 0, 32);
    System.arraycopy(clientPubKey, 0, tooLongData, 32, 65);
    tooLongData[97] = (byte) 0xAA;
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, tooLongData));
    assertEquals(0x6A80, response.getSw());

    // Empty data
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, new byte[0]));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key does not start with 0x04 (uncompressed indicator) -----
    byte[] badPubKey = new byte[65];
    badPubKey[0] = 0x03; // compressed-style prefix instead of 0x04
    byte[] dataWithBadPubKey = new byte[97];
    for (int i = 0; i < 32; i++) dataWithBadPubKey[i] = (byte) i;
    System.arraycopy(badPubKey, 0, dataWithBadPubKey, 32, 65);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithBadPubKey));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key is 65 bytes but starts with 0x00 (invalid) -----
    byte[] zeroPrefixPubKey = new byte[65];
    zeroPrefixPubKey[0] = 0x00;
    byte[] dataWithZeroPrefix = new byte[97];
    for (int i = 0; i < 32; i++) dataWithZeroPrefix[i] = (byte) i;
    System.arraycopy(zeroPrefixPubKey, 0, dataWithZeroPrefix, 32, 65);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithZeroPrefix));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key is 64 bytes (too short for uncompressed) -----
    byte[] shortPubKey = new byte[64];
    shortPubKey[0] = 0x04;
    for (int i = 1; i < shortPubKey.length; i++) {
      shortPubKey[i] = (byte) (i + 10);
    }
    byte[] dataWithShortPubKey = new byte[96];
    for (int i = 0; i < 32; i++) dataWithShortPubKey[i] = (byte) i;
    System.arraycopy(shortPubKey, 0, dataWithShortPubKey, 32, 64);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithShortPubKey));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key format is valid (0x04, 65 bytes) but not a valid curve point -----
    byte[] invalidCurvePubKey = new byte[65];
    invalidCurvePubKey[0] = 0x04;
    // X = 0, Y = 0 — not on secp256k1 (y² ≠ x³ + 7)
    byte[] dataWithInvalidCurveKey = new byte[97];
    for (int i = 0; i < 32; i++) dataWithInvalidCurveKey[i] = (byte) i;
    System.arraycopy(invalidCurvePubKey, 0, dataWithInvalidCurveKey, 32, 65);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithInvalidCurveKey));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: wrong P1 or P2 -----
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x01, 0x00, dataWithBadPubKey));
    assertEquals(0x6A86, response.getSw());

    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x01, dataWithBadPubKey));
    assertEquals(0x6A86, response.getSw());

    // ----- Good case: valid openSecureChannel -----
    // Generate a proper secp256k1 key pair for the client
    java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC", "BC");
    org.bouncycastle.jce.spec.ECParameterSpec ecSpec =
        org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
    g.initialize(ecSpec);
    java.security.KeyPair clientKeyPair = g.generateKeyPair();
    byte[] clientPublicKey = ((org.bouncycastle.jce.interfaces.ECPublicKey) clientKeyPair.getPublic())
        .getQ().getEncoded(false);

    // Build the request: 32-byte salt + 65-byte uncompressed public key
    byte[] requestData = new byte[97];
    byte[] clientSalt = new byte[32];
    for (int i = 0; i < 32; i++) {
      clientSalt[i] = (byte) (i + 1);
    }
    System.arraycopy(clientSalt, 0, requestData, 0, 32);
    System.arraycopy(clientPublicKey, 0, requestData, 32, 65);

    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, requestData));
    assertEquals(0x9000, response.getSw());

    // Response should be: 65-byte card ephemeral public key + ECDSA signature
    byte[] respData = response.getData();
    assertTrue(respData.length >= PUBKEY_SIZE + 70, "Response too short");
    assertTrue(respData.length <= PUBKEY_SIZE + 72, "Response too long");

    // Card's ephemeral public key should start with 0x04
    assertEquals(0x04, respData[0]);

    // ----- Good case: open a second secure channel (fresh key exchange) -----
    java.security.KeyPair clientKeyPair2 = g.generateKeyPair();
    byte[] clientPublicKey2 = ((org.bouncycastle.jce.interfaces.ECPublicKey) clientKeyPair2.getPublic())
        .getQ().getEncoded(false);

    byte[] requestData2 = new byte[97];
    byte[] clientSalt2 = new byte[32];
    for (int i = 0; i < 32; i++) {
      clientSalt2[i] = (byte) (i + 100);
    }
    System.arraycopy(clientSalt2, 0, requestData2, 0, 32);
    System.arraycopy(clientPublicKey2, 0, requestData2, 32, 65);

    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, requestData2));
    assertEquals(0x9000, response.getSw());
    respData = response.getData();
    assertEquals(0x04, respData[0]);
  }

  @Test
  @DisplayName("GET STATUS command")
  void getStatusTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    // Good case. Since the order of test execution is undefined, the test cannot know if the keys are initialized or not.
    // Additionally, support for public key derivation is hw dependent.
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSw());
    ApplicationStatus status = new ApplicationStatus(response.getData());

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      assertEquals(3, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());

      response = cmdSet.verifyPIN("123456");
      assertEquals(0x63C2, response.getSw());
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x9000, response.getSw());
      status = new ApplicationStatus(response.getData());
      assertEquals(2, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x9000, response.getSw());
      status = new ApplicationStatus(response.getData());
      assertEquals(3, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());
    } else {
      assertEquals((byte) 0xff, status.getPINRetryCount());
      assertEquals((byte) 0xff, status.getPUKRetryCount());
    }
  }

  @Test
  @DisplayName("VERIFY PIN command")
  @Capabilities("credentialsManagement")
  void verifyPinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Wrong format
    response = cmdSet.verifyPIN("12345");
    assertEquals(0x6a80, response.getSw());

    response = cmdSet.verifyPIN("12345a");
    assertEquals(0x6a80, response.getSw());

    // Wrong PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    // Correct PIN
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Alt PIN
    response = cmdSet.verifyPIN("024680");
    assertEquals(0x9000, response.getSw());    

    // Check max retry counter
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSw());

    response = cmdSet.verifyPIN("024680");
    assertEquals(0x63C0, response.getSw());

    resetAndSelectAndOpenSC();

    // Unblock PIN to make further tests possible
    response = cmdSet.unblockPIN("012345678901", "024680");
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("CHANGE PIN command")
  @Capabilities("credentialsManagement")
  void changePinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Wrong P1
    response = cmdSet.changePIN(0x03, "123456");
    assertEquals(0x6a86, response.getSw());

    // Test wrong PIN formats (non-digits, too short, too long)
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "654a21");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "54321");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "7654321");
    assertEquals(0x6A80, response.getSw());

    // Test wrong PUK formats
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "210987654a21");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "10987654321");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "3210987654321");
    assertEquals(0x6A80, response.getSw());

    // Change PIN correctly, check that after PIN change the PIN remains validated
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "654321");
    assertEquals(0x9000, response.getSw());

    // Reset card and verify that the new PIN has really been set
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSw());

    // Change PUK
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "210987654321");
    assertEquals(0x9000, response.getSw());

    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C2, response.getSw());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C1, response.getSw());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSw());

    // Reset the PIN with the new PUK
    response = cmdSet.unblockPIN("210987654321", "000000");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Reset PUK
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "012345678901");
    assertEquals(0x9000, response.getSw());

    // Alt PIN
    response = cmdSet.verifyPIN("024680");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x9000, response.getSw());
    
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "024680");
    assertEquals(0x9000, response.getSw());

    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("UNBLOCK PIN command")
  @Capabilities("credentialsManagement")
  void unblockPinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.unblockPIN("012345678901", "000000");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Condition violation: PIN is not blocked
    response = cmdSet.unblockPIN("012345678901", "000000");
    assertEquals(0x6985, response.getSw());

    // Block the PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSw());

    // Wrong PUK formats (too short, too long)
    response = cmdSet.unblockPIN("12345678901", "000000");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.unblockPIN("1234567890123", "000000");
    assertEquals(0x6A80, response.getSw());

    // Wrong PUK
    response = cmdSet.unblockPIN("123456789010", "000000");
    assertEquals(0x63C4, response.getSw());

    // Correct PUK
    response = cmdSet.unblockPIN("012345678901", "654321");
    assertEquals(0x9000, response.getSw());

    // Check that PIN has been changed and unblocked
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSw());

    // Reset the PIN to make further tests possible
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "000000");
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("LOAD KEY (external) is disabled; clone import path preserved")
  void loadKeyDisabledTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    KeyPair kp = keypairGenerator().generateKeyPair();
    // Every external LOAD KEY entry returns 0x6D00.
    assertEquals(0x6D00, cmdSet.loadKey(kp).getSw());
    assertEquals(0x6D00, cmdSet.loadKey(new byte[]{(byte)0xA1,0x02,(byte)0x80,0x00}, KeycardApplet.LOAD_KEY_P1_EC).getSw());
  }

  @Test
  @DisplayName("LOAD KEY command")
  @Capabilities("keyManagement")
  void loadKeyTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    KeyPair kp = keypairGenerator().generateKeyPair();
    // External LOAD KEY is disabled on the no-mnemonic SKU.
    assertEquals(0x6D00, cmdSet.loadKey(kp).getSw());
  }

  @Test
  @DisplayName("GENERATE MNEMONIC command")
  @Capabilities("keyManagement")
  void generateMnemonicTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    // GENERATE MNEMONIC is disabled: this SKU never produces BIP-39 words.
    assertEquals(0x6D00, cmdSet.generateMnemonic(4).getSw());
    assertEquals(0x6D00, cmdSet.generateMnemonic(8).getSw());
  }

  @Test
  @DisplayName("REMOVE KEY command")
  @Capabilities("keyManagement")
  void removeKeyTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.removeKey();
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.removeKey();
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSw());

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    assertTrue(cmdSet.getKeyInitializationStatus());

    // Good case
    response = cmdSet.removeKey();
    assertEquals(0x9000, response.getSw());

    assertFalse(cmdSet.getKeyInitializationStatus());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    ApplicationInfo info = new ApplicationInfo(response.getData());
    assertEquals(0, info.getKeyUID().length);
  }

  @Test
  @DisplayName("FACTORY RESET command")
  @Capabilities("factoryReset")
  void factoryResetTest() throws Exception {    
    // Invalid P1 P2
    APDUResponse response = sdkChannel.send(new APDUCommand(0x80, KeycardApplet.INS_FACTORY_RESET, 0, 0, new byte[0]));
    assertEquals(0x6a86, response.getSw());

    // Good case
    response = cmdSet.factoryReset();
    assertEquals(0x9000, response.getSw());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    assertFalse(cmdSet.getApplicationInfo().isInitializedCard());

    initCard(cmdSet);

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    assertFalse(cmdSet.getKeyInitializationStatus());
  }

  @Test
  @DisplayName("GET CHALLENGE command")
  @Capabilities("secureChannel")
  void getChallengeWithSecureChannelTest() throws Exception {
    cmdSet.autoOpenSecureChannel();

    APDUResponse response = cmdSet.getChallenge(16);
    assertEquals(0x9000, response.getSw());
    assertEquals(16, response.getData().length);

    response = cmdSet.getChallenge(32);
    assertEquals(0x9000, response.getSw());
    assertEquals(32, response.getData().length);

    int maxSecureChannelChallengeLength = SecureChannelV2.SC_MAX_RESPONSE_LENGTH;

    response = cmdSet.getChallenge(maxSecureChannelChallengeLength);
    assertEquals(0x9000, response.getSw());
    assertEquals(maxSecureChannelChallengeLength, response.getData().length);

    response = cmdSet.getChallenge(maxSecureChannelChallengeLength + 1);
    assertEquals(0x6A86, response.getSw());

    response = cmdSet.getChallenge(255);
    assertEquals(0x6A86, response.getSw());
  }

  @Test
  @DisplayName("GENERATE KEY command")
  @Capabilities("keyManagement")
  void generateKeyTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.generateKey();
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.generateKey();
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Good case
    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSw());
    byte[] keyUID = response.getData();

    response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
    assertEquals(0x9000, response.getSw());
    byte[] pubKey = response.getData();

    verifyKeyUID(keyUID, Arrays.copyOfRange(pubKey, 4, pubKey.length));
  }


  @Test
  @DisplayName("SIGN command")
  void signTest() throws Exception {
    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.signWithPath(hash, "m", false);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.signWithPath(hash, "m", false);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (!cmdSet.getApplicationInfo().hasMasterKey()) {
      response = cmdSet.generateKey();
      assertEquals(0x9000, response.getSw());
    }

    // Correctly sign with master key (path "m" = master)
    response = cmdSet.signWithPath(hash, "m", false);
    verifySignResp(data, response);

    // Sign with derived path
    String derivedPath = "m/2";
    response = cmdSet.signWithPath(hash, derivedPath, false);
    verifySignResp(data, response);

    // Sign Schnorr
    if (TARGET != TARGET_SIMULATOR) {
      response = cmdSet.signWithPath(hash, derivedPath, KeycardCommandSet.SIGN_P2_BIP340_SCHNORR, false);
      verifySchnorrSignResp(data, response);
    }

    // Alt PIN
    response = cmdSet.verifyPIN("024680");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.signWithPath(hash, derivedPath, false);
    verifySignResp(data, response);
  }

  private void verifySchnorrSignResp(byte[] data, APDUResponse response) throws Exception {
    assertEquals(0x9000, response.getSw());
    byte[] sig = response.getData();
    byte[] keyData = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);

    assertEquals(65, keyData.length);
    assertEquals((byte) 4, keyData[0]);
    assertEquals(66, sig.length);
    assertEquals((byte) 0x88, sig[0]);
    assertEquals((byte) 64, sig[1]);
  }

  private void verifySignResp(byte[] data, APDUResponse response) throws Exception {
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    assertEquals(0x9000, response.getSw());
    byte[] sig = response.getData();
    byte[] keyData = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(keyData), ecSpec);
    ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

    signature.initVerify(cardKey);
    assertEquals(65, keyData.length);
    signature.update(data);
    assertTrue(signature.verify(sig));
    assertFalse(isMalleable(sig));
  }

  @Test
  @DisplayName("EXPORT KEY command")
  void exportKey() throws Exception {
    byte[] hash = sha256("some data to sign".getBytes());
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
      assertEquals(0x6985, response.getSw());
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // No-mnemonic SKU: seed is generated on-chip (external LOAD KEY disabled), so
    // no known vector can be injected. Verify export self-consistently instead.
    assertEquals(0x9000, cmdSet.generateKey().getSw());

    // Master public export == the public key SIGN returns for the same path "m".
    response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
    assertEquals(0x9000, response.getSw());
    byte[] exportedPub = extractPublicKeyFromExport(response.getData());
    byte[] signedPub = extractPublicKeyFromSignature(cmdSet.signWithPath(hash, "m", false).getData());
    assertArrayEquals(signedPub, exportedPub);

    byte[] walletPath = new byte[] {(byte) 0x80,0,0,0x2B,(byte) 0x80,0,0,0x3C,(byte) 0x80,0,0x06,0x2D,0,0,0,0};

    // Derived public export works.
    assertEquals(0x9000, cmdSet.exportKey(walletPath, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true).getSw());

    // Private export blocked on every path (red line).
    assertEquals(0x6A81, cmdSet.exportKey(walletPath, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false).getSw());
    assertEquals(0x6A81, cmdSet.exportKey(new byte[] {(byte) 0x80,0,0,0x2B,(byte) 0x80,0,0,0x3C,(byte) 0x80,0,0x06,0x2D,0,0,0,0,0,0,0,0}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false).getSw());

    // Extended public (xpub) export works.
    assertEquals(0x9000, cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC).getSw());
  }

  @Test
  @DisplayName("EXPORT KEY private mode is disabled (no-mnemonic red line)")
  void exportKeyPrivateBlockedTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());

    byte[] eip1581 = new byte[] {(byte) 0x80,0,0,0x2B,(byte)0x80,0,0,0x3C,(byte)0x80,0,0x06,0x2D,0,0,0,0,0,0,0,0};
    byte[] wallet  = new byte[] {(byte) 0x80,0,0,0x2B,(byte)0x80,0,0,0x3C,(byte)0x80,0,0x06,0x2D,0,0,0,0};

    // Private export blocked on EVERY path -> 0x6A81
    assertEquals(0x6A81, cmdSet.exportKey(eip1581, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC).getSw());
    assertEquals(0x6A81, cmdSet.exportKey(wallet, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC).getSw());

    // Public + xpub still work
    assertEquals(0x9000, cmdSet.exportKey(wallet, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_PUBLIC_ONLY).getSw());
    assertEquals(0x9000, cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false,
        KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC).getSw());
  }

  @Test
  @DisplayName("LEE Keys")
  void leeKeysTest() throws Exception {
    byte[] seed = Mnemonic.toBinarySeed("fan empower output between game genius forest bulk party small arm shuffle", "");
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    // LOAD KEY (incl. LEE variant) is disabled on the no-mnemonic SKU.
    assertEquals(0x6D00, cmdSet.loadLEEKey(seed).getSw());
  }

  @Test
  @DisplayName("EXPORT LEE is disabled (no-mnemonic red line)")
  void exportLeeDisabledTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    APDUResponse r = cmdSet.exportLEEKey(new byte[] {(byte) 0x80,0,0,0x2B,(byte)0x80,0,0,0x3C}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
    assertEquals(0x6D00, r.getSw());
  }

  @Test
  @DisplayName("EXPORT BIP85 is disabled (no-mnemonic red line)")
  void exportBip85DisabledTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    APDUResponse r = cmdSet.exportBIP85(64, new KeyPath("m/83696968'/0'/0'").getData());
    assertEquals(0x6D00, r.getSw());
  }

  @Test
  @DisplayName("BIP85")
  void bip85Test() throws Exception {
    cmdSet.autoOpenSecureChannel();
    // BIP85 export is disabled on the no-mnemonic SKU.
    assertEquals(0x6D00, cmdSet.exportBIP85(64, new KeyPath("m/83696968'/0'/0'").getData()).getSw());
  }  

  @Test
  @DisplayName("STORE/GET DATA")
  void storeGetDataTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.storeData(new byte[20], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.storeData(new byte[20], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Data too long
    response = cmdSet.storeData(new byte[128], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x6A80, response.getSw());

    byte[] data = new byte[127];

    for (int i = 0; i < 127; i++) {
      data[i] = (byte) i;
    }

    // Correct data
    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_PUBLIC);

    assertEquals(0x9000, response.getSw());

    // Read data back with secure channel
    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(data, response.getData());

    // Empty data
    response = cmdSet.storeData(new byte[0], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());
    assertEquals(0, response.getData().length);

    // Shorter data
    data = Arrays.copyOf(data, 20);
    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());

    // GET DATA without Secure Channel
    cmdSet.select().checkOK();
    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x6985, response.getSw());

    if (cmdSet.getApplicationInfo().hasNDEFCapability()) {
      byte[] ndefData = {
              (byte) 0x00, (byte) 0x24, (byte) 0xd4, (byte) 0x0f, (byte) 0x12, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
              (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d,
              (byte) 0x3a, (byte) 0x70, (byte) 0x6b, (byte) 0x67, (byte) 0x69, (byte) 0x6d, (byte) 0x2e, (byte) 0x73,
              (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x75, (byte) 0x73, (byte) 0x2e, (byte) 0x65, (byte) 0x74,
              (byte) 0x68, (byte) 0x65, (byte) 0x72, (byte) 0x65, (byte) 0x75, (byte) 0x6d
      };

      // Security condition violation: SecureChannel not open
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();

      // Security condition violation: PIN not verified
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());

      // Good case.
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x9000, response.getSw());

      // Good case with no length.
      response = cmdSet.setNDEF(Arrays.copyOfRange(ndefData, 2, ndefData.length));
      assertEquals(0x9000, response.getSw());

      // Long message with segmentation
      response = cmdSet.setNDEF(Hex.decode("c101000001b45402656e5468697320697320612072656c61746976656c79206c6f6e672074657874207265636f72642074686174206669747320696e2061626f75742035303020627974657320736f207468617420492063616e2074657374207365676d656e746174696f6e206f66207265636f726473207573696e6720746865206e657720616e6420696d70726f766564204e444546206170706c65742e20546869732069732071756974652061206c6f6e67207465787420746f2077726974652062757420686579204920616d206865726520666f7220746869732e204920776f6e277420636f707920616e64207061737465207468652073616d6520737472696e67206f76657220616e64206f766572206265636175736520492077616e7420746f206d616b6520737572652064617461206973207265616420636f72726563746c7920616e6420746865726520617265206e6f20737472616e67652073746974636865732e2049276420616c736f206c696b6520746f206d616b6520737572652065766572797468696e6720697320617320636c6f736520746f207265616c20776f726c6420757361676520617320706f737369626c65"));
      assertEquals(0x9000, response.getSw());
    }

    data[0] = (byte) 0xAA;

    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_CASH);
    assertEquals(0x9000, response.getSw());

    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());
    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    assertArrayEquals(data, info.getPubData());
  }

  @Test
  @DisplayName("GET DATA NDEF with output segmentation")
  @Capabilities("ndef")
  void getDataNdefSegmentationTest() throws Exception {
    cmdSet.autoOpenSecureChannel();

    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Create a 500-byte NDEF payload with a deterministic pattern
    int payloadLen = 500;
    byte[] payload = new byte[payloadLen];
    for (int i = 0; i < payloadLen; i++) {
      payload[i] = (byte) (i & 0xFF);
    }

    // Build NDEF data: 2-byte big-endian length + payload
    byte[] ndefData = new byte[2 + payloadLen];
    ndefData[0] = (byte) (payloadLen >> 8);
    ndefData[1] = (byte) (payloadLen & 0xFF);
    System.arraycopy(payload, 0, ndefData, 2, payloadLen);

    // Store the NDEF data (SDK handles input segmentation automatically)
    response = cmdSet.setNDEF(payload);
    assertEquals(0x9000, response.getSw());

    // Total stored length = payload (500) + 2-byte length header = 502 bytes
    int totalLen = payloadLen + 2;
    int maxChunk = (SecureChannelV2.SC_MAX_RESPONSE_LENGTH / 4) * 4;

    // Verify individual segment boundaries
    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) 0);
    assertEquals(0x9000, response.getSw());
    assertEquals(maxChunk, response.getData().length, "First segment should be max size");

    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) (maxChunk / 4));
    assertEquals(0x9000, response.getSw());
    assertEquals(maxChunk, response.getData().length, "Second segment should be max size");

    // Last segment
    int lastOffset = (short) (maxChunk * 2);
    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) (lastOffset / 4));
    assertEquals(0x9000, response.getSw());
    assertEquals(totalLen - lastOffset, response.getData().length, "Last segment size mismatch");

    // Offset beyond data fails empty
    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) ((totalLen + 3) / 4));
    assertEquals(0x6A86, response.getSw());
  }

  @Test
  @DisplayName("Test the Cash applet (SELECT only)")
  void cashTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    APDUResponse response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());

    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    assertTrue(info.getAppVersion() > 0);
  }

  @Test
  @DisplayName("CASH CSK tap-sign: signs SHA256(domain||challenge||counter) with the card's CSK key")
  void cashTapSignTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    APDUResponse response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());

    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    byte[] pubKeyData = info.getPubKey();

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(pubKeyData), ecSpec);
    ECPublicKey ecPublicKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

    byte[] challenge = "hello-antfun-tap".getBytes();
    // domain-separated message the card is expected to hash:
    byte[] domain = "ANTFUN-TAP-v1".getBytes();

    // send tap-sign (same P2 sign-format value used for ECDSA elsewhere, e.g. signTest/KeycardCommandSet.SIGN_P2_ECDSA)
    APDUResponse resp = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    assertEquals(0x9000, resp.getSw());
    byte[] data = resp.getData();
    assertTrue(data.length > 2, "response must be counter(2)||sig");
    int counter = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
    byte[] sig = Arrays.copyOfRange(data, 2, data.length);

    byte[] toHash = new byte[domain.length + challenge.length + 2];
    System.arraycopy(domain, 0, toHash, 0, domain.length);
    System.arraycopy(challenge, 0, toHash, domain.length, challenge.length);
    toHash[domain.length + challenge.length] = (byte) ((counter >> 8) & 0xFF);
    toHash[domain.length + challenge.length + 1] = (byte) (counter & 0xFF);
    byte[] expectedHash = sha256(toHash);

    // verify the ECDSA signature over expectedHash against the CSK pubkey (mirrors verifySignResp's BC verification)
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    signature.initVerify(ecPublicKey);
    signature.update(toHash);
    assertTrue(signature.verify(sig));

    // sanity: the hash the card is documented to sign matches SHA256(domain||challenge||counter)
    assertEquals(32, expectedHash.length);

    // a different challenge must yield a different signature
    byte[] resp2Data = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, "different".getBytes())).getData();
    byte[] sig2 = Arrays.copyOfRange(resp2Data, 2, resp2Data.length);
    assertFalse(Arrays.equals(sig, sig2));
  }

  @Test
  @DisplayName("CASH CSK tap-sign: binds a persistent monotonic counter")
  void cashTapCounterTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    APDUResponse response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());

    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    byte[] pubKeyData = info.getPubKey();

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(pubKeyData), ecSpec);
    ECPublicKey ecPublicKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

    byte[] challenge = "meeting-proof".getBytes();

    APDUResponse r1 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    assertEquals(0x9000, r1.getSw());
    int counter1 = ((r1.getData()[0] & 0xFF) << 8) | (r1.getData()[1] & 0xFF);
    byte[] sig1 = Arrays.copyOfRange(r1.getData(), 2, r1.getData().length);

    APDUResponse r2 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    assertEquals(0x9000, r2.getSw());
    int counter2 = ((r2.getData()[0] & 0xFF) << 8) | (r2.getData()[1] & 0xFF);
    assertTrue(counter2 > counter1, "counter must strictly increase");

    // sig1 must verify over SHA256(domain || challenge || counter1) -- i.e. the counter is bound into the signature
    byte[] domain = "ANTFUN-TAP-v1".getBytes();
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(domain);
    bos.write(challenge);
    bos.write((counter1 >> 8) & 0xFF);
    bos.write(counter1 & 0xFF);
    byte[] preimage1 = bos.toByteArray();

    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    signature.initVerify(ecPublicKey);
    signature.update(preimage1);
    assertTrue(signature.verify(sig1), "signature must verify against the pre-image bound to the returned counter");

    // negative control: sig1 must NOT verify against a pre-image using counter2 -- proves the counter is
    // actually baked into the signed hash, not merely echoed alongside an unrelated signature.
    ByteArrayOutputStream wrongBos = new ByteArrayOutputStream();
    wrongBos.write(domain);
    wrongBos.write(challenge);
    wrongBos.write((counter2 >> 8) & 0xFF);
    wrongBos.write(counter2 & 0xFF);
    Signature signature2 = Signature.getInstance("SHA256withECDSA", "BC");
    signature2.initVerify(ecPublicKey);
    signature2.update(wrongBos.toByteArray());
    assertFalse(signature2.verify(sig1), "sig1 must not verify against a pre-image built with a different counter");
  }

  @Test
  @DisplayName("TICKET tap-sign: independent TSK key signs SHA256(domain||challenge||counter), isolated from CSK/cash key")
  void ticketTapSignTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    APDUResponse sel = cashCmdSet.select();
    assertEquals(0x9000, sel.getSw());
    byte[] cashPubData = new CashApplicationInfo(sel.getData()).getPubKey(); // cash/CSK key

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

    // challenge carries eventId||nonce (opaque bytes to the card in this core version)
    byte[] challenge = "event-BKK2026|nonce-abc123".getBytes();
    byte[] domain = "ANTFUN-TICKET-v1".getBytes();

    APDUResponse resp = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    assertEquals(0x9000, resp.getSw());
    byte[] data = resp.getData();
    assertTrue(data.length > 67, "response must be pubkey(65)||counter(2)||sig");

    byte[] tskPub = Arrays.copyOfRange(data, 0, 65);
    int counter = ((data[65] & 0xFF) << 8) | (data[66] & 0xFF);
    byte[] sig = Arrays.copyOfRange(data, 67, data.length);

    // TSK pubkey must be a valid secp256k1 point AND different from the cash/CSK pubkey (key isolation)
    assertFalse(Arrays.equals(tskPub, cashPubData), "TSK key must be independent from cash/CSK key");
    ECPublicKey tskKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC")
        .generatePublic(new ECPublicKeySpec(ecSpec.getCurve().decodePoint(tskPub), ecSpec));

    // sig verifies over SHA256(domain||challenge||counter) against the TSK pubkey
    byte[] toHash = new byte[domain.length + challenge.length + 2];
    System.arraycopy(domain, 0, toHash, 0, domain.length);
    System.arraycopy(challenge, 0, toHash, domain.length, challenge.length);
    toHash[domain.length + challenge.length] = (byte) ((counter >> 8) & 0xFF);
    toHash[domain.length + challenge.length + 1] = (byte) (counter & 0xFF);
    Signature v = Signature.getInstance("SHA256withECDSA", "BC");
    v.initVerify(tskKey);
    v.update(toHash);
    assertTrue(v.verify(sig), "ticket sig must verify against the TSK pubkey");

    // isolation: the ticket sig must NOT verify against the cash/CSK pubkey
    ECPublicKey cashKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC")
        .generatePublic(new ECPublicKeySpec(ecSpec.getCurve().decodePoint(cashPubData), ecSpec));
    Signature v2 = Signature.getInstance("SHA256withECDSA", "BC");
    v2.initVerify(cashKey);
    v2.update(toHash);
    assertFalse(v2.verify(sig), "ticket sig must not verify against the cash/CSK key");

    // a different eventId (different challenge) must yield a different signature
    byte[] resp2 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, "event-DXB2026|nonce-abc123".getBytes())).getData();
    byte[] sig2 = Arrays.copyOfRange(resp2, 67, resp2.length);
    assertFalse(Arrays.equals(sig, sig2), "different eventId must yield a different signature");
  }

  @Test
  @DisplayName("TICKET tap-sign: persistent monotonic counter is bound into the signature")
  void ticketTapCounterTest() throws Exception {
    new CashCommandSet(sdkChannel).select();
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    byte[] domain = "ANTFUN-TICKET-v1".getBytes();
    byte[] challenge = "event-BKK2026|checkin".getBytes();

    APDUResponse r1 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    assertEquals(0x9000, r1.getSw());
    byte[] d1 = r1.getData();
    byte[] tskPub = Arrays.copyOfRange(d1, 0, 65);
    int counter1 = ((d1[65] & 0xFF) << 8) | (d1[66] & 0xFF);
    byte[] sig1 = Arrays.copyOfRange(d1, 67, d1.length);

    // Cross-pollination guard: a CSK tap (0xD7) in between must NOT touch ticketCounter.
    sdkChannel.send(new APDUCommand(0x80, (byte) 0xD7, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, "csk-noise".getBytes()));

    APDUResponse r2 = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD8, 0x00, KeycardCommandSet.SIGN_P2_ECDSA, challenge));
    byte[] d2 = r2.getData();
    int counter2 = ((d2[65] & 0xFF) << 8) | (d2[66] & 0xFF);
    assertEquals(counter1 + 1, counter2, "ticketCounter must increment by exactly 1 per ticket sign, independent of CSK taps");

    ECPublicKey tskKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC")
        .generatePublic(new ECPublicKeySpec(ecSpec.getCurve().decodePoint(tskPub), ecSpec));

    // sig1 verifies over the pre-image bound to counter1
    ByteArrayOutputStream ok = new ByteArrayOutputStream();
    ok.write(domain); ok.write(challenge);
    ok.write((counter1 >> 8) & 0xFF); ok.write(counter1 & 0xFF);
    Signature s1 = Signature.getInstance("SHA256withECDSA", "BC");
    s1.initVerify(tskKey); s1.update(ok.toByteArray());
    assertTrue(s1.verify(sig1), "sig1 must verify against the pre-image bound to counter1");

    // negative control: sig1 must NOT verify against a pre-image using counter2
    ByteArrayOutputStream bad = new ByteArrayOutputStream();
    bad.write(domain); bad.write(challenge);
    bad.write((counter2 >> 8) & 0xFF); bad.write(counter2 & 0xFF);
    Signature s2 = Signature.getInstance("SHA256withECDSA", "BC");
    s2.initVerify(tskKey); s2.update(bad.toByteArray());
    assertFalse(s2.verify(sig1), "sig1 must not verify against a pre-image built with a different counter");
  }

  @Test
  @DisplayName("Mnemonic load and derivation")
  @Tag("manual")
  void mnemonicTest() throws Exception {
    // NOTE: GENERATE MNEMONIC / LOAD KEY(seed) are disabled on the no-mnemonic SKU; this manual test no longer reflects shipping behavior.
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    byte[] seed = Mnemonic.toBinarySeed("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will", "");
    response = cmdSet.loadKey(seed);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.exportKey("m", false, true);
    assertEquals(0x9000, response.getSw());

    BIP32KeyPair pubKey = BIP32KeyPair.fromTLV(response.getData());
    assertEquals("04cc620f846055ed43995391ca5e490c52251ea40453f64a0515bef84c24a653a7c4e02b9de56f66d9ee58dc6b591b534f5a20c0550b2c33a086b90b866cf70799", Hex.toHexString(pubKey.getPublicKey()));

    response = cmdSet.exportKey("m/43'/60'/1581'/0'/0", false, true);
    assertEquals(0x9000, response.getSw());

    pubKey = BIP32KeyPair.fromTLV(response.getData());
    assertEquals("04e7370d118461e1ab01f3e86e88c4b0c7b92cecb79c5e320cef73dda912f173beae74df15090b6405a274963c054cdfe6ac7843a302c260390d1fe776008f310e", Hex.toHexString(pubKey.getPublicKey()));
  }

  @Test
  @DisplayName("Sign actual Ethereum transaction")
  @Tag("manual")
  void signTransactionTest() throws Exception {
    // NOTE: relies on external LOAD KEY, disabled on the no-mnemonic SKU; manual/out-of-scope.
    // Initialize credentials
    Web3j web3j = Web3j.build(new HttpService());
    Credentials wallet1 = WalletUtils.loadCredentials("testwallet", "testwallets/wallet1.json");
    Credentials wallet2 = WalletUtils.loadCredentials("testwallet", "testwallets/wallet2.json");

    // Load keys on card
    cmdSet.autoOpenSecureChannel();
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());
    response = cmdSet.loadKey(wallet1.getEcKeyPair());
    assertEquals(0x9000, response.getSw());

    // Verify balance
    System.out.println("Wallet 1 balance: " + web3j.ethGetBalance(wallet1.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance());
    System.out.println("Wallet 2 balance: " + web3j.ethGetBalance(wallet2.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance());

    // Create transaction
    BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
    BigInteger weiValue = Convert.toWei(BigDecimal.valueOf(1.0), Convert.Unit.FINNEY).toBigIntegerExact();
    BigInteger nonce = web3j.ethGetTransactionCount(wallet1.getAddress(), DefaultBlockParameterName.LATEST).send().getTransactionCount();

    RawTransaction rawTransaction = RawTransaction.createEtherTransaction(nonce, gasPrice, Transfer.GAS_LIMIT, wallet2.getAddress(), weiValue);

    // Sign transaction
    byte[] txBytes = TransactionEncoder.encode(rawTransaction);
    Sign.SignatureData signature = signMessage(txBytes);

    Method encode = TransactionEncoder.class.getDeclaredMethod("encode", RawTransaction.class, Sign.SignatureData.class);
    encode.setAccessible(true);

    // Send transaction
    byte[] signedMessage = (byte[]) encode.invoke(null, rawTransaction, signature);
    String hexValue = "0x" + Hex.toHexString(signedMessage);
    EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

    if (ethSendTransaction.hasError()) {
      System.out.println("Transaction Error: " + ethSendTransaction.getError().getMessage());
    }

    assertFalse(ethSendTransaction.hasError());
  }


  private KeyPairGenerator keypairGenerator() throws Exception {
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ecSpec);

    return g;
  }

  private byte[] extractSignature(byte[] sig) {
    int off = sig[4] + 5;
    return Arrays.copyOfRange(sig, off, off + sig[off + 1] + 2);
  }

  private byte[] extractPublicKeyFromSignature(byte[] sig) {
    assertEquals(KeycardApplet.TLV_SIGNATURE_TEMPLATE, sig[0]);
    assertEquals((byte) 0x81, sig[1]);
    assertEquals(KeycardApplet.TLV_PUB_KEY, sig[3]);

    return Arrays.copyOfRange(sig, 5, 5 + sig[4]);
  }

  private byte[] extractPublicKeyFromExport(byte[] keyTemplate) {
    TinyBERTLV tlv = new TinyBERTLV(keyTemplate);
    tlv.enterConstructed(KeycardApplet.TLV_KEY_TEMPLATE);
    return tlv.readPrimitive(KeycardApplet.TLV_PUB_KEY);
  }

  private void reset() {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        simulator.reset();
        break;
      case TARGET_CARD:
        apduChannel.getCard().getATR();
        break;
      default:
        break;
    }
  }

  private void resetAndSelectAndOpenSC() throws Exception {
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      reset();
      cmdSet.select();
      cmdSet.autoOpenSecureChannel();
    }
  }

  private void assertMnemonic(int expectedLength, byte[] data) {
    short[] shorts = new short[data.length / 2];
    assertEquals(expectedLength, shorts.length);
    ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).asShortBuffer().get(shorts);

    boolean[] bits = new boolean[11 * shorts.length];
    int i = 0;

    for (short mIdx : shorts) {
      assertTrue(mIdx >= 0 && mIdx < 2048);
      for (int j = 0; j < 11; ++j) {
        bits[i++] = (mIdx & (1 << (10 - j))) > 0;
      }
    }

    data = new byte[bits.length / 33 * 4];

    for (i = 0; i < bits.length / 33 * 32; ++i) {
      data[i / 8] |= (bits[i] ? 1 : 0) << (7 - (i % 8));
    }

    byte[] check = sha256(data);

    for (i = bits.length / 33 * 32; i < bits.length; ++i) {
      if ((check[(i - bits.length / 33 * 32) / 8] & (1 << (7 - (i % 8))) ^ (bits[i] ? 1 : 0) << (7 - (i % 8))) != 0) {
        fail("Checksum is invalid");
      }
    }
  }

  private void verifyExportedKey(byte[] keyTemplate, KeyPair keyPair, byte[] chainCode, int[] path, boolean publicOnly, boolean extendedPublic) {
    if (!cmdSet.getApplicationInfo().hasKeyManagementCapability()) {
      return;
    }

    DeterministicKey dk = deriveKey(keyPair, chainCode, path);
    ECKey key = dk.decompress();
    assertEquals(KeycardApplet.TLV_KEY_TEMPLATE, keyTemplate[0]);
    
    if (publicOnly) {
      assertEquals(KeycardApplet.TLV_PUB_KEY, keyTemplate[2]);
      byte[] pubKey = Arrays.copyOfRange(keyTemplate, 4, 4 + keyTemplate[3]);
      
      assertArrayEquals(key.getPubKey(), pubKey);
      int templateLen = 2 + pubKey.length;

      if (extendedPublic) {
        byte[] chain = Arrays.copyOfRange(keyTemplate, templateLen + 4, templateLen + 4 + keyTemplate[3 + templateLen]);
        assertEquals(KeycardApplet.TLV_CHAIN_CODE, keyTemplate[2 + templateLen]);        
        assertArrayEquals(dk.getChainCode(), chain);
        templateLen += 2 + chain.length;
      }      

      assertEquals(templateLen, keyTemplate[1]);
      assertEquals(templateLen + 2, keyTemplate.length);
    } else {
      assertEquals(KeycardApplet.TLV_PRIV_KEY, keyTemplate[2]);
      byte[] privateKey = Arrays.copyOfRange(keyTemplate, 4, 4 + keyTemplate[3]);

      byte[] tPrivKey = key.getPrivKey().toByteArray();

      if (tPrivKey[0] == 0x00) {
        tPrivKey = Arrays.copyOfRange(tPrivKey, 1, tPrivKey.length);
      }

      assertArrayEquals(tPrivKey, privateKey);
    }
  }

  private DeterministicKey deriveKey(KeyPair keyPair, byte[] chainCode, int[] path) {
    DeterministicKey key = HDKeyDerivation.createMasterPrivKeyFromBytes(((org.bouncycastle.jce.interfaces.ECPrivateKey) keyPair.getPrivate()).getD().toByteArray(), chainCode);

    for (int i : path) {
      key = HDKeyDerivation.deriveChildKey(key, new ChildNumber(i));
    }

    return key;
  }

  private boolean isMalleable(byte[] sig) {
    int rLen = sig[3];
    int sOff = 6 + rLen;
    int sLen = sig.length - rLen - 6;

    BigInteger s = new BigInteger(Arrays.copyOfRange(sig, sOff, sOff + sLen));
    BigInteger limit = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);

    return s.compareTo(limit) >= 1;
  }

  /**
   * Signs a signature using the card. Returns a SignatureData object which contains v, r and s. The algorithm to do
   * this is as follow:
   *
   * 1) The Keccak-256 hash of transaction is generated off-card
   * 2) A SIGN command is sent to the card to sign the precomputed hash
   * 3) The returned data is the public key and the signature
   * 4) The signature and public key can be used to generate the v value. The v value allows to recover the public key
   *    from the signature. Here we use the web3j implementation through reflection
   * 5) v, r and s are the final signature to append to the transaction
   *
   * @param message the raw transaction
   * @return the signature data
   */
  private Sign.SignatureData signMessage(byte[] message) throws Exception {
    byte[] messageHash = Hash.sha3(message);

    APDUResponse response = cmdSet.signWithPath(messageHash, "m", false);
    assertEquals(0x9000, response.getSw());
    byte[] respData = response.getData();
    byte[] rawSig = extractSignature(respData);

    int rLen = rawSig[3];
    int sOff = 6 + rLen;
    int sLen = rawSig.length - rLen - 6;

    BigInteger r = new BigInteger(Arrays.copyOfRange(rawSig, 4, 4 + rLen));
    BigInteger s = new BigInteger(Arrays.copyOfRange(rawSig, sOff, sOff + sLen));

    Class<?> ecdsaSignature = Class.forName("org.web3j.crypto.Sign$ECDSASignature");
    Constructor<?> ecdsaSignatureConstructor = ecdsaSignature.getDeclaredConstructor(BigInteger.class, BigInteger.class);
    ecdsaSignatureConstructor.setAccessible(true);
    Object sig = ecdsaSignatureConstructor.newInstance(r, s);
    Method m = ecdsaSignature.getMethod("toCanonicalised");
    m.setAccessible(true);
    sig = m.invoke(sig);

    Method recoverFromSignature = Sign.class.getDeclaredMethod("recoverFromSignature", int.class, ecdsaSignature, byte[].class);
    recoverFromSignature.setAccessible(true);

    byte[] pubData = extractPublicKeyFromSignature(respData);
    BigInteger publicKey = new BigInteger(Arrays.copyOfRange(pubData, 1, pubData.length));

    int recId = -1;
    for (int i = 0; i < 4; i++) {
      BigInteger k = (BigInteger) recoverFromSignature.invoke(null, i, sig, messageHash);
      if (k != null && k.equals(publicKey)) {
        recId = i;
        break;
      }
    }
    if (recId == -1) {
      throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
    }

    int headerByte = recId + 27;

    Field rF = ecdsaSignature.getDeclaredField("r");
    rF.setAccessible(true);
    Field sF = ecdsaSignature.getDeclaredField("s");
    sF.setAccessible(true);
    r = (BigInteger) rF.get(sig);
    s = (BigInteger) sF.get(sig);

    // 1 header + 32 bytes for R + 32 bytes for S
    byte v = (byte) headerByte;
    byte[] rB = Numeric.toBytesPadded(r, 32);
    byte[] sB = Numeric.toBytesPadded(s, 32);

    return new Sign.SignatureData(v, rB, sB);
  }

  private void verifyKeyUID(byte[] keyUID, ECPublicKey pubKey) {
    verifyKeyUID(keyUID, pubKey.getQ().getEncoded(false));
  }

  private void verifyKeyUID(byte[] keyUID, byte[] pubKey) {
    assertArrayEquals(sha256(pubKey), keyUID);
  }

  @Test
  @DisplayName("CLONE: verify a peer DAK certificate in-chip against the provisioned CA")
  void cloneVerifyPeerCertTest() throws Exception {
    // A peer card's device (DAK) keypair on secp256k1
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger peerPriv = new BigInteger("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 16);
    ECPublicKey peerPub = (ECPublicKey) kf.generatePublic(
        new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(peerPriv), spec));
    byte[] peerPubBytes = peerPub.getQ().getEncoded(false); // 65-byte uncompressed

    // CA signs the peer's pubkey -> the DAK certificate signature (DER ECDSA over SHA256(peerPub))
    Signature caSigner = Signature.getInstance("SHA256withECDSA", "BC");
    caSigner.initSign(caKeyPair.getPrivate());
    caSigner.update(peerPubBytes);
    byte[] caSig = caSigner.sign();

    byte[] caPubBytes = ((ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(false); // 65-byte uncompressed

    // Provision the CA public key into the applet (spike: via command; production: at perso)
    APDUResponse setCa = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x00, 0x00, caPubBytes));
    assertEquals(0x9000, setCa.getSw());

    // Certificate = peerPubkey(65) || CA signature(DER); the applet must verify it in-chip
    byte[] cert = new byte[peerPubBytes.length + caSig.length];
    System.arraycopy(peerPubBytes, 0, cert, 0, peerPubBytes.length);
    System.arraycopy(caSig, 0, cert, peerPubBytes.length, caSig.length);

    APDUResponse verify = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x01, 0x00, cert));
    assertEquals(0x9000, verify.getSw());
  }

  @Test
  @DisplayName("CLONE: reject a peer certificate not signed by the provisioned CA")
  void cloneRejectForgedCertTest() throws Exception {
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger peerPriv = new BigInteger("0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000", 16);
    ECPublicKey peerPub = (ECPublicKey) kf.generatePublic(
        new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(peerPriv), spec));
    byte[] peerPubBytes = peerPub.getQ().getEncoded(false);

    // Sign with a NON-CA key (a forger), not the provisioned CA
    BigInteger forgerPriv = new BigInteger("dead00beef00cafe00babe00f00d00feed00c0ffee00deadbeef00cafe00babe", 16);
    java.security.KeyPair forger = new java.security.KeyPair(
        kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(forgerPriv), spec)),
        kf.generatePrivate(new org.bouncycastle.jce.spec.ECPrivateKeySpec(forgerPriv, spec)));
    Signature forgerSigner = Signature.getInstance("SHA256withECDSA", "BC");
    forgerSigner.initSign(forger.getPrivate());
    forgerSigner.update(peerPubBytes);
    byte[] forgedSig = forgerSigner.sign();

    byte[] caPubBytes = ((ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(false);
    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x00, 0x00, caPubBytes)).getSw());

    byte[] cert = new byte[peerPubBytes.length + forgedSig.length];
    System.arraycopy(peerPubBytes, 0, cert, 0, peerPubBytes.length);
    System.arraycopy(forgedSig, 0, cert, peerPubBytes.length, forgedSig.length);

    APDUResponse verify = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x01, 0x00, cert));
    assertNotEquals(0x9000, verify.getSw());
    assertEquals(0x6A80, verify.getSw()); // SW_WRONG_DATA
  }

  @Test
  @DisplayName("CLONE EXPORT end-to-end: peer B (played by the test) recovers card A's master key")
  void cloneExportEndToEndTest() throws Exception {
    // --- Card A: open secure channel, verify PIN, generate a master key; capture its key UID ---
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    APDUResponse gen = cmdSet.generateKey();
    assertEquals(0x9000, gen.getSw());
    byte[] keyUID = gen.getData(); // sha256(uncompressed master public key)

    // --- Provision the CA public key into A ---
    byte[] caPubBytes = ((ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(false);
    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x00, 0x00, caPubBytes)).getSw());

    // --- Peer B keypair + DAK certificate (peerPub signed by the CA) ---
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger bPriv = new BigInteger("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 16);
    ECPublicKey bPub = (ECPublicKey) kf.generatePublic(
        new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(bPriv), spec));
    byte[] bPubBytes = bPub.getQ().getEncoded(false);
    Signature caSigner = Signature.getInstance("SHA256withECDSA", "BC");
    caSigner.initSign(caKeyPair.getPrivate());
    caSigner.update(bPubBytes);
    byte[] caSig = caSigner.sign();

    byte[] nonce = new byte[16];
    for (int i = 0; i < 16; i++) nonce[i] = (byte) (0xB0 + i);

    // CLONE_EXPORT input = nonce(16) || peerPub(65) || CA signature
    byte[] in = new byte[16 + bPubBytes.length + caSig.length];
    System.arraycopy(nonce, 0, in, 0, 16);
    System.arraycopy(bPubBytes, 0, in, 16, bPubBytes.length);
    System.arraycopy(caSig, 0, in, 16 + bPubBytes.length, caSig.length);

    APDUResponse export = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in));
    assertEquals(0x9000, export.getSw());
    byte[] out = export.getData();
    assertEquals(65 + 64 + 16, out.length); // e_A_pub(65) || ct(64) || tag(16)
    byte[] eaPub = Arrays.copyOfRange(out, 0, 65);
    byte[] ct = Arrays.copyOfRange(out, 65, 129);
    byte[] tag = Arrays.copyOfRange(out, 129, 145);

    org.bouncycastle.math.ec.ECPoint shared = spec.getCurve().decodePoint(eaPub).multiply(bPriv).normalize();
    byte[] x = Numeric.toBytesPadded(shared.getAffineXCoord().toBigInteger(), 32);
    byte[] okm = hkdfSha256(nonce, x, "ANTFUN-CLONE-v1".getBytes(), 32);
    byte[] encKey = Arrays.copyOfRange(okm, 0, 16);
    byte[] macKey = Arrays.copyOfRange(okm, 16, 32);

    // Tag must authenticate the ciphertext
    byte[] expectedTag = Arrays.copyOfRange(hmacSha256(macKey, ct), 0, 16);
    assertArrayEquals(expectedTag, tag, "clone ciphertext tag must verify");

    javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding", "BC");
    aes.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(encKey, "AES"),
             new javax.crypto.spec.IvParameterSpec(new byte[16]));
    byte[] pt = aes.doFinal(ct);
    byte[] masterPriv = Arrays.copyOfRange(pt, 0, 32);
    byte[] recoveredPub = spec.getG().multiply(new BigInteger(1, masterPriv)).normalize().getEncoded(false);
    assertArrayEquals(keyUID, sha256(recoveredPub), "peer B must recover the same master key as card A");
  }

  @Test
  @DisplayName("CLONE EXPORT: requires PIN verification")
  void cloneExportRequiresPinTest() throws Exception {
    // First establish that a master key EXISTS and persists across a reset, so that the only
    // condition distinguishing this session from a successful export is the PIN. Otherwise a
    // 0x6985 here could just as well come from the pre-existing masterPrivate.isInitialized()
    // check, and the test would pass even if the PIN guard were deleted.
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());

    // Power-cycle the simulator: this de-validates the PIN (OwnerPIN.isValidated resets on
    // reset), but the master key persists in EEPROM. Re-select without re-verifying the PIN.
    reset();
    cmdSet.select();

    byte[] caPubBytes = ((ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(false);
    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x00, 0x00, caPubBytes)).getSw());

    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger bPriv = new BigInteger("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 16);
    byte[] bPubBytes = ((ECPublicKey) kf.generatePublic(
        new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(bPriv), spec))).getQ().getEncoded(false);
    Signature caSigner = Signature.getInstance("SHA256withECDSA", "BC");
    caSigner.initSign(caKeyPair.getPrivate());
    caSigner.update(bPubBytes);
    byte[] caSig = caSigner.sign();

    byte[] in = new byte[16 + bPubBytes.length + caSig.length];
    for (int i = 0; i < 16; i++) in[i] = (byte) (0xE0 + i);
    System.arraycopy(bPubBytes, 0, in, 16, bPubBytes.length);
    System.arraycopy(caSig, 0, in, 16 + bPubBytes.length, caSig.length);

    // No verifyPIN in this (post-reset) session, but the master key IS initialized -> the
    // 0x6985 below can only come from the PIN guard.
    APDUResponse r = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in));
    assertEquals(0x6985, r.getSw()); // SW_CONDITIONS_NOT_SATISFIED
  }

  @Test
  @DisplayName("CLONE IMPORT: requires PIN verification")
  void cloneImportRequiresPinTest() throws Exception {
    // Fresh applet (per @BeforeEach isolation): PIN is set but NOT verified in this session.
    // The PIN guard is the very first statement in CLONE_P1_IMPORT (before the length check),
    // so even a short/dummy payload must be refused with 0x6985 purely on account of the PIN.
    byte[] in = new byte[8];
    APDUResponse r = sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x03, 0x00, in));
    assertEquals(0x6985, r.getSw()); // SW_CONDITIONS_NOT_SATISFIED
  }

  @Test
  @DisplayName("CLONE EXPORT: reject a reused nonce (anti-replay)")
  void cloneExportRejectsReusedNonceTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());
    byte[] caPubBytes = ((ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(false);
    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x00, 0x00, caPubBytes)).getSw());

    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger bPriv = new BigInteger("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 16);
    byte[] bPubBytes = ((ECPublicKey) kf.generatePublic(
        new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(bPriv), spec))).getQ().getEncoded(false);
    Signature caSigner = Signature.getInstance("SHA256withECDSA", "BC");
    caSigner.initSign(caKeyPair.getPrivate());
    caSigner.update(bPubBytes);
    byte[] caSig = caSigner.sign();

    byte[] nonce = new byte[16];
    for (int i = 0; i < 16; i++) nonce[i] = (byte) (0xC0 + i);
    byte[] in = new byte[16 + bPubBytes.length + caSig.length];
    System.arraycopy(nonce, 0, in, 0, 16);
    System.arraycopy(bPubBytes, 0, in, 16, bPubBytes.length);
    System.arraycopy(caSig, 0, in, 16 + bPubBytes.length, caSig.length);

    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in)).getSw());
    // Same nonce again -> rejected
    assertEquals(0x6A80, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x02, 0x00, in)).getSw());
  }

  @Test
  @DisplayName("CLONE IMPORT round-trip: applet imports a master key sent by peer A")
  void cloneImportRoundTripTest() throws Exception {
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

    // A known master key (masterPriv || chainCode) that peer A will send
    byte[] masterPriv = new byte[32];
    byte[] chainCode = new byte[32];
    for (int i = 0; i < 32; i++) { masterPriv[i] = (byte) (0x11 + i); chainCode[i] = (byte) (0x80 + i); }
    byte[] seed = new byte[64];
    System.arraycopy(masterPriv, 0, seed, 0, 32);
    System.arraycopy(chainCode, 0, seed, 32, 32);

    // Peer A ephemeral key; ECDH against the applet's device PUBLIC key (test knows identKeyPair)
    BigInteger aEph = new BigInteger("0a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00010203040506070809", 16);
    byte[] aEphPub = spec.getG().multiply(aEph).normalize().getEncoded(false);
    org.bouncycastle.jce.interfaces.ECPublicKey devPub = (org.bouncycastle.jce.interfaces.ECPublicKey) identKeyPair.getPublic();
    org.bouncycastle.math.ec.ECPoint shared = devPub.getQ().multiply(aEph).normalize();
    byte[] x = Numeric.toBytesPadded(shared.getAffineXCoord().toBigInteger(), 32);

    byte[] nonce = new byte[16];
    for (int i = 0; i < 16; i++) nonce[i] = (byte) (0xD0 + i);
    byte[] okm = hkdfSha256(nonce, x, "ANTFUN-CLONE-v1".getBytes(), 32);
    byte[] encKey = Arrays.copyOfRange(okm, 0, 16);
    byte[] macKey = Arrays.copyOfRange(okm, 16, 32);

    javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding", "BC");
    aes.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(encKey, "AES"),
             new javax.crypto.spec.IvParameterSpec(new byte[16]));
    byte[] ct = aes.doFinal(seed);
    byte[] tag = Arrays.copyOfRange(hmacSha256(macKey, ct), 0, 16);

    byte[] in = new byte[16 + 65 + 64 + 16];
    System.arraycopy(nonce, 0, in, 0, 16);
    System.arraycopy(aEphPub, 0, in, 16, 65);
    System.arraycopy(ct, 0, in, 81, 64);
    System.arraycopy(tag, 0, in, 145, 16);

    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x03, 0x00, in)).getSw());

    // The applet must now hold that master key: its key UID = sha256(uncompressed master pub)
    byte[] expectedPub = spec.getG().multiply(new BigInteger(1, masterPriv)).normalize().getEncoded(false);
    byte[] info = cmdSet.select().checkOK().getData();
    byte[] uid = new ApplicationInfo(info).getKeyUID();
    assertArrayEquals(sha256(expectedPub), uid, "applet must control the imported master key");
  }

  @Test
  @DisplayName("CLONE IMPORT: reject a tampered ciphertext")
  void cloneImportRejectsTamperedCtTest() throws Exception {
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

    // A known master key (masterPriv || chainCode) that peer A will send
    byte[] masterPriv = new byte[32];
    byte[] chainCode = new byte[32];
    for (int i = 0; i < 32; i++) { masterPriv[i] = (byte) (0x11 + i); chainCode[i] = (byte) (0x80 + i); }
    byte[] seed = new byte[64];
    System.arraycopy(masterPriv, 0, seed, 0, 32);
    System.arraycopy(chainCode, 0, seed, 32, 32);

    // Peer A ephemeral key; ECDH against the applet's device PUBLIC key (test knows identKeyPair)
    BigInteger aEph = new BigInteger("0a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00010203040506070809", 16);
    byte[] aEphPub = spec.getG().multiply(aEph).normalize().getEncoded(false);
    org.bouncycastle.jce.interfaces.ECPublicKey devPub = (org.bouncycastle.jce.interfaces.ECPublicKey) identKeyPair.getPublic();
    org.bouncycastle.math.ec.ECPoint shared = devPub.getQ().multiply(aEph).normalize();
    byte[] x = Numeric.toBytesPadded(shared.getAffineXCoord().toBigInteger(), 32);

    byte[] nonce = new byte[16];
    for (int i = 0; i < 16; i++) nonce[i] = (byte) (0xD0 + i);
    byte[] okm = hkdfSha256(nonce, x, "ANTFUN-CLONE-v1".getBytes(), 32);
    byte[] encKey = Arrays.copyOfRange(okm, 0, 16);
    byte[] macKey = Arrays.copyOfRange(okm, 16, 32);

    javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding", "BC");
    aes.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(encKey, "AES"),
             new javax.crypto.spec.IvParameterSpec(new byte[16]));
    byte[] ct = aes.doFinal(seed);
    byte[] tag = Arrays.copyOfRange(hmacSha256(macKey, ct), 0, 16);

    byte[] in = new byte[16 + 65 + 64 + 16];
    System.arraycopy(nonce, 0, in, 0, 16);
    System.arraycopy(aEphPub, 0, in, 16, 65);
    System.arraycopy(ct, 0, in, 81, 64);
    System.arraycopy(tag, 0, in, 145, 16);

    in[81] ^= 0x01; // corrupt first ciphertext byte

    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x6A80, sdkChannel.send(new APDUCommand(0x80, (byte) 0xD6, 0x03, 0x00, in)).getSw());
  }

  private static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int len) throws Exception {
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(new javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"));
    byte[] prk = mac.doFinal(ikm);
    mac.init(new javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"));
    mac.update(info);
    mac.update((byte) 0x01);
    return Arrays.copyOfRange(mac.doFinal(), 0, len);
  }

  private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(data);
  }

  @Test
  @DisplayName("No-mnemonic red line: no APDU path exports private key or injects external seed")
  void noMnemonicRedLineTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());
    byte[] p = new byte[] {(byte)0x80,0,0,0x2B,(byte)0x80,0,0,0x3C,(byte)0x80,0,0x06,0x2D,0,0,0,0};
    // Disabled whole-commands -> 0x6D00
    assertEquals(0x6D00, cmdSet.generateMnemonic(4).getSw());
    assertEquals(0x6D00, cmdSet.loadKey(keypairGenerator().generateKeyPair()).getSw());
    assertEquals(0x6D00, cmdSet.exportLEEKey(new byte[]{(byte)0x80,0,0,0x2B,(byte)0x80,0,0,0x3C}, KeycardApplet.DERIVE_P1_SOURCE_MASTER).getSw());
    assertEquals(0x6D00, cmdSet.exportBIP85(64, new KeyPath("m/83696968'/0'/0'").getData()).getSw());
    // Private export blocked -> 0x6A81; public/xpub survive
    assertEquals(0x6A81, cmdSet.exportKey(p, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardCommandSet.EXPORT_KEY_P2_PRIVATE_AND_PUBLIC).getSw());
    assertEquals(0x9000, cmdSet.exportKey(p, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC).getSw());
    // On-chip generation still works
    assertTrue(cmdSet.getKeyInitializationStatus());
  }

  @Test
  @DisplayName("VAULT: store(import) & export entropy round-trips, PIN-gated (seed-storage SKU)")
  void vaultStoreExportTest() throws Exception {
    assumeFalse(KeycardApplet.NO_MNEMONIC, "seed-storage SKU only");
    cmdSet.autoOpenSecureChannel();

    byte[] entropy = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); // 32B

    // PIN gate: store before PIN -> 0x6985
    assertEquals(0x6985, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, entropy).getSw());
    // PIN gate: export before PIN -> 0x6985
    assertEquals(0x6985, cmdSet.exportSecret().getSw());

    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // store(import) then export -> identical
    assertEquals(0x9000, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, entropy).getSw());
    APDUResponse exp = cmdSet.exportSecret();
    assertEquals(0x9000, exp.getSw());
    assertArrayEquals(entropy, exp.getData());
  }

  @Test
  @DisplayName("VAULT: invalid entropy length rejected (seed-storage SKU)")
  void vaultPinAndLengthTest() throws Exception {
    assumeFalse(KeycardApplet.NO_MNEMONIC, "seed-storage SKU only");
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // 17 bytes is not a valid BIP-39 entropy length -> 0x6A80
    assertEquals(0x6A80, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, new byte[17]).getSw());
    // 24 bytes IS valid -> 0x9000, and round-trips
    byte[] e24 = new byte[24];
    for (short i = 0; i < 24; i++) e24[i] = (byte) (i + 1);
    assertEquals(0x9000, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, e24).getSw());
    assertArrayEquals(e24, cmdSet.exportSecret().getData());
  }

  @Test
  @DisplayName("VAULT: factory reset wipes entropy (seed-storage SKU)")
  void vaultFactoryResetWipeTest() throws Exception {
    assumeFalse(KeycardApplet.NO_MNEMONIC, "seed-storage SKU only");
    cmdSet.autoOpenSecureChannel();

    byte[] entropy = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    // Store entropy
    assertEquals(0x9000, cmdSet.storeSecret(KeycardApplet.STORE_SECRET_P1_IMPORT, 0, entropy).getSw());
    // Verify it exists
    APDUResponse exp = cmdSet.exportSecret();
    assertEquals(0x9000, exp.getSw());
    assertArrayEquals(entropy, exp.getData());

    // Factory reset
    assertEquals(0x9000, cmdSet.factoryReset().getSw());

    // Re-init and re-open secure channel
    cmdSet.select();
    initCard(cmdSet);
    cmdSet.select();
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // NOTE: black-box limitation — exportSecret() is gated by secretLen, so this test
    // verifies the export gate re-engages after factory reset (secretLen == 0). The
    // byte-level wipe of secretStore (Util.arrayFillNonAtomic in factoryReset()) cannot
    // be observed via APDU and is verified by code review, not this assertion.
    // After reset, secretLen should be 0, so export should fail with 0x6985
    assertEquals(0x6985, cmdSet.exportSecret().getSw());
  }
}
