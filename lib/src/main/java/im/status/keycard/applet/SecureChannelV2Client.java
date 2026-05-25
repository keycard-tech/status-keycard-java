package im.status.keycard.applet;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.List;
import java.util.Arrays;

/**
 * Client-side implementation of the Secure Channel Protocol v2 (AES-CCM variant).
 *
 * Protocol flow:
 * <ol>
 *   <li>Handshake: ECDHE on secp256k1 + HKDF-SHA256 key derivation</li>
 *   <li>Card authentication: ECDSA-SHA256 signature over the full key exchange transcript</li>
 *   <li>Encrypted commands: AES-128-CCM (T=8, L=13) with implicit per-session nonce counter</li>
 * </ol>
 *
 * All traffic after the handshake is wrapped in a single command type:
 * {@code [0x80 | 0x18 | 0x00 | 0x00 | LC'] || ciphertext || tag(8B)}
 *
 * The inner APDU (including CLA, INS, P1, P2, LC, and data) is fully encrypted.
 * The ISO-level SW is always 0x9000 (decrypt OK) or 0x6982 (decrypt error);
 * the real command SW is inside the encrypted response payload.
 *
 * Unlike V1, V2 does not use pairing. Each session establishes independent keys
 * via ECDHE, authenticated by the card's persistent identity key certificate.
 */
public class SecureChannelV2Client implements SecureChannel {

  // Protocol constants
  private static final byte[] PROTOCOL_LABEL = {
      's', 'c', '_', 'v', '2', '_', 'c', 'c', 'm', (byte) 0x00
  };

  static final short HKDF_SALT_SIZE = 32;
  static final short PUBKEY_SIZE = 65;       // uncompressed secp256k1 point
  static final short ECDH_SHARED_X_SIZE = 32;
  static final short OKM_SIZE = 32;
  static final short AES_KEY_SIZE = 16;
  static final short CCM_TAG_SIZE = 8;
  static final short CCM_NONCE_SIZE = 13;

  static final byte INS_OPEN_SECURE_CHANNEL = (byte) 0x10;
  static final byte INS_SECURED_APDU = (byte) 0x18;

  // Trusted CA public keys for certificate verification (compressed, 33 bytes each)
  private final List<byte[]> caPublicKeys;
  // Whitelisted card identity public keys (compressed, 33 bytes each)
  // Allows accepting specific cards even when their CA is not trusted
  private final List<byte[]> whitelistedCardPublicKeys;

  // Session state
  private final SecretKeySpec keyH2C = new SecretKeySpec(new byte[AES_KEY_SIZE], "AES");
  private final SecretKeySpec keyC2H = new SecretKeySpec(new byte[AES_KEY_SIZE], "AES");
  private Cipher cipherH2C;  // card-to-client decrypt
  private Cipher cipherC2H;  // client-to-card encrypt
  private byte[] nonceCounter;
  private boolean open;

  // Card identity (set during handshake)
  private byte[] cardIdentPub;  // compressed, 33 bytes

  // Handshake ephemeral key (kept for debug/testing)
  private byte[] clientEphPub;

  private final SecureRandom random;

  /**
   * Creates a V2 secure channel client with the given set of trusted CA public keys
   * and optionally whitelisted card identity public keys.
   *
   * During certificate verification, a card is accepted if either:
   * <ul>
   *   <li>The CA public key recovered from its certificate matches one of the trusted CA keys, or</li>
   *   <li>The card's identity public key is in the whitelist</li>
   * </ul>
   *
   * @param caPublicKeys list of compressed secp256k1 CA public keys (33 bytes each)
   * @param whitelistedCardPublicKeys list of compressed card identity public keys (33 bytes each)
   */
  public SecureChannelV2Client(List<byte[]> caPublicKeys, List<byte[]> whitelistedCardPublicKeys) {
    if (caPublicKeys == null) {
      throw new IllegalArgumentException("caPublicKeys must not be null");
    }
    if (whitelistedCardPublicKeys == null) {
      throw new IllegalArgumentException("whitelistedCardPublicKeys must not be null");
    }
    this.caPublicKeys = Collections.unmodifiableList(caPublicKeys);
    this.whitelistedCardPublicKeys = Collections.unmodifiableList(whitelistedCardPublicKeys);
    this.random = new SecureRandom();
    initCiphers();
  }

  private void initCiphers() {
    try {
      cipherH2C = Cipher.getInstance("AES/CCM/NoPadding", "BC");
      cipherC2H = Cipher.getInstance("AES/CCM/NoPadding", "BC");
      nonceCounter = new byte[CCM_NONCE_SIZE];
    } catch (Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  // ── SecureChannel interface implementation ──────────────────────────

  @Override
  public void autoOpenSecureChannel(CardChannel apduChannel)
      throws IOException, APDUException {
    byte[] salt = new byte[HKDF_SALT_SIZE];
    random.nextBytes(salt);

    // Generate client ephemeral key pair
    KeyPair ephKeyPair = generateEphemeralKeyPair();
    clientEphPub = getUncompressedPublicKey(ephKeyPair.getPublic());

    // Build request: hkdf_salt || client_eph_pub (uncompressed)
    byte[] requestData = new byte[(int) (HKDF_SALT_SIZE + PUBKEY_SIZE)];
    System.arraycopy(salt, 0, requestData, 0, HKDF_SALT_SIZE);
    System.arraycopy(clientEphPub, 0, requestData, HKDF_SALT_SIZE, PUBKEY_SIZE);

    // Send OPEN_SECURE_CHANNEL
    APDUCommand cmd = new APDUCommand(0x80, INS_OPEN_SECURE_CHANNEL, 0, 0, requestData);
    APDUResponse resp = apduChannel.send(cmd);
    resp.checkOK("OPEN SECURE CHANNEL failed");

    processHandshakeResponse(salt, ephKeyPair.getPrivate(), resp.getData());
  }

  @Override
  public void autoPair(CardChannel apduChannel, byte pairingMode, byte[] sharedSecret)
      throws IOException, APDUException {
    throw new UnsupportedOperationException("Pairing is not supported in Secure Channel V2");
  }

  @Override
  public void autoUnpair(CardChannel apduChannel) throws IOException, APDUException {
    throw new UnsupportedOperationException("Unpairing is not supported in Secure Channel V2");
  }

  @Override
  public void unpairOthers(CardChannel apduChannel) throws IOException, APDUException {
    throw new UnsupportedOperationException("Unpairing is not supported in Secure Channel V2");
  }

  @Override
  public APDUResponse openSecureChannel(CardChannel apduChannel, byte index, byte[] data)
      throws IOException {
    open = false;
    APDUCommand cmd = new APDUCommand(0x80, INS_OPEN_SECURE_CHANNEL, 0, 0, data);
    return apduChannel.send(cmd);
  }

  @Override
  public APDUResponse mutuallyAuthenticate(CardChannel apduChannel) throws IOException {
    throw new UnsupportedOperationException(
        "Mutual authentication is not a separate step in Secure Channel V2");
  }

  @Override
  public APDUResponse mutuallyAuthenticate(CardChannel apduChannel, byte[] data)
      throws IOException {
    throw new UnsupportedOperationException(
        "Mutual authentication is not a separate step in Secure Channel V2");
  }

  @Override
  public APDUResponse pair(CardChannel apduChannel, byte p1, byte p2, byte[] data)
      throws IOException {
    throw new UnsupportedOperationException("Pairing is not supported in Secure Channel V2");
  }

  @Override
  public APDUResponse unpair(CardChannel apduChannel, byte p1) throws IOException {
    throw new UnsupportedOperationException("Unpairing is not supported in Secure Channel V2");
  }

  @Override
  public APDUCommand protectedCommand(int cla, int ins, int p1, int p2, byte[] data) {
    if (!open) {
      return new APDUCommand(cla, ins, p1, p2, data);
    }

    // Build inner APDU: CLA | INS | P1 | P2 | LC | data
    ByteArrayOutputStream inner = new ByteArrayOutputStream();
    inner.write(cla & 0xFF);
    inner.write(ins & 0xFF);
    inner.write(p1 & 0xFF);
    inner.write(p2 & 0xFF);
    inner.write(data.length & 0xFF);
    inner.write(data, 0, data.length);

    byte[] innerApdu = inner.toByteArray();
    byte[] ciphertext = encryptCCM(innerApdu);

    return new APDUCommand(0x80, INS_SECURED_APDU, 0, 0, ciphertext);
  }

  @Override
  public APDUResponse transmit(CardChannel apduChannel, APDUCommand apdu) throws IOException {
    APDUResponse resp = apduChannel.send(apdu);

    if (resp.getSw() != 0x9000) {
      open = false;
      return resp;
    }

    if (!open) {
      return resp;
    }

    byte[] ciphertext = resp.getData();
    byte[] plaintext = decryptCCM(ciphertext);

    return new APDUResponse(plaintext);
  }

  @Override
  public Pairing getPairing() {
    return null; // V2 does not use pairing
  }

  @Override
  public void setPairing(Pairing pairing) {
    // No-op: V2 does not use pairing
  }

  @Override
  public void reset() {
    open = false;
    keyH2C.getEncoded(); // ensure keys are valid references
    Arrays.fill(keyH2C.getEncoded(), (byte) 0);
    Arrays.fill(keyC2H.getEncoded(), (byte) 0);
    Arrays.fill(nonceCounter, (byte) 0);
    cardIdentPub = null;
    clientEphPub = null;
  }

  // ── Handshake processing ────────────────────────────────────────────

  /**
   * Processes the card's handshake response.
   *
   * @param salt         the HKDF salt sent by the client
   * @param clientEphPriv the client's ephemeral private key
   * @param cardResponse the raw response data (card_eph_pub || DER_signature)
   */
  void processHandshakeResponse(byte[] salt, PrivateKey clientEphPriv, byte[] cardResponse) throws APDUException {
    // Parse card response: card_eph_pub (65B) || sig (DER, variable)
    if (cardResponse.length < PUBKEY_SIZE + 2) {
      throw new APDUException("Invalid handshake response: too short");
    }

    byte[] cardEphPub = Arrays.copyOfRange(cardResponse, 0, (int) PUBKEY_SIZE);
    byte[] signature = Arrays.copyOfRange(cardResponse, (int) PUBKEY_SIZE, cardResponse.length);

    // ECDH key agreement
    byte[] sharedSecret = computeECDH(clientEphPriv, cardEphPub);

    // HKDF-SHA256 key derivation
    byte[] okm = hkdfExpand(salt, sharedSecret, PROTOCOL_LABEL, OKM_SIZE);

    // Set session keys: key_h2c = OKM[0..15], key_c2h = OKM[16..31]
    System.arraycopy(okm, 0, keyH2C.getEncoded(), 0, AES_KEY_SIZE);
    System.arraycopy(okm, AES_KEY_SIZE, keyC2H.getEncoded(), 0, AES_KEY_SIZE);

    initCiphers();

    // Verify card's ECDSA signature over transcript
    // transcript = hkdf_salt || client_eph_pub || card_eph_pub
    verifyCardSignature(salt, clientEphPub, cardEphPub, signature);

    // Initialize nonce counter to zero
    Arrays.fill(nonceCounter, (byte) 0);
    open = true;
  }

  private void verifyCardSignature(byte[] salt, byte[] clientPub, byte[] cardPub, byte[] signature) throws APDUException {
    try {
      // Hash the transcript
      MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
      md.update(salt);
      md.update(clientPub);
      md.update(cardPub);
      byte[] transcriptHash = md.digest();

      if (cardIdentPub == null) {
        throw new APDUException("Card identity public key not available");
      }

      // Verify the ECDSA signature using standard JCA API
      Signature verifier = Signature.getInstance("NONEwithECDSA", "BC");
      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      ECPublicKeySpec keySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(cardIdentPub), ecSpec);
      ECPublicKey identKey = (ECPublicKey) KeyFactory.getInstance("EC", "BC").generatePublic(keySpec);
      verifier.initVerify(identKey);
      verifier.update(transcriptHash);

      if (!verifier.verify(signature)) {
        throw new APDUException("Card authentication failed: invalid signature");
      }
    } catch (APDUException e) {
      throw e;
    } catch (Exception e) {
      throw new APDUException("Card authentication failed: " + e.getMessage());
    }
  }

  // ── Certificate handling ────────────────────────────────────────────

  /**
   * Parses the card's identity certificate from the SELECT response and
   * validates the CA public key against the known anchor.
   *
   * @param certData the 98-byte certificate from the SELECT response
   * @throws IOException if CA verification fails
   */
  public void setCardCertificate(byte[] certData) throws IOException {
    try {
      Certificate cert = Certificate.fromTLV(certData);
      cardIdentPub = cert.getIdentPub();

      // Check if the card's identity public key is whitelisted
      boolean whitelisted = isCardWhitelisted(cardIdentPub);

      // Check if the CA public key is trusted
      byte[] caPub = cert.getPublicKey(); // recovered CA public key (compressed)
      boolean caTrusted = isCaTrusted(caPub);

      if (!caTrusted && !whitelisted) {
        throw new IOException("Card certificate verification failed: unknown CA public key and card not whitelisted");
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException("Failed to parse card certificate: " + e.getMessage());
    }
  }

  /**
   * Returns the card's identity public key (set during handshake).
   *
   * @return compressed public key, or null if not yet set
   */
  public byte[] getCardIdentPub() {
    return cardIdentPub;
  }

  /**
   * Checks if the given card identity public key is in the whitelist.
   *
   * @param identPub compressed card identity public key (33 bytes)
   * @return true if the key is whitelisted
   */
  public boolean isCardWhitelisted(byte[] identPub) {
    for (byte[] key : whitelistedCardPublicKeys) {
      if (Arrays.equals(key, identPub)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if the given CA public key is trusted.
   *
   * @param caPub compressed CA public key (33 bytes)
   * @return true if the key is trusted
   */
  public boolean isCaTrusted(byte[] caPub) {
    for (byte[] key : caPublicKeys) {
      if (Arrays.equals(key, caPub)) {
        return true;
      }
    }
    return false;
  }

  // ── Cryptographic helpers ───────────────────────────────────────────

  private KeyPair generateEphemeralKeyPair() {
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
      kpg.initialize(new ECGenParameterSpec("secp256k1"), random);
      return kpg.generateKeyPair();
    } catch (Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  private byte[] getUncompressedPublicKey(PublicKey pubKey) {
    return ((ECPublicKey) pubKey).getQ().getEncoded(false);
  }

  private byte[] computeECDH(PrivateKey clientPriv, byte[] cardPubUncompressed) {
    try {
      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

      // Decode the card's uncompressed public key
      ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(cardPubUncompressed), ecSpec);
      ECPublicKey cardPub = (ECPublicKey) KeyFactory.getInstance("EC", "BC").generatePublic(cardKeySpec);

      // Perform ECDH key agreement
      KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
      ka.init(clientPriv);
      ka.doPhase(cardPub, true);
      byte[] sharedSecret = ka.generateSecret();

      // ECDH via BC may return 64 bytes (XY) or 32 bytes (X only).
      // The card uses ALG_EC_SVDP_DH_PLAIN which returns XY, taking first 32 as X.
      if (sharedSecret.length == ECDH_SHARED_X_SIZE * 2) {
        return Arrays.copyOfRange(sharedSecret, 0, ECDH_SHARED_X_SIZE);
      } else if (sharedSecret.length == ECDH_SHARED_X_SIZE) {
        return sharedSecret;
      } else {
        // Normalize to 32 bytes
        byte[] result = new byte[ECDH_SHARED_X_SIZE];
        System.arraycopy(sharedSecret, 0, result, 0, Math.min(sharedSecret.length, ECDH_SHARED_X_SIZE));
        return result;
      }
    } catch (Exception e) {
      throw new RuntimeException("ECDH key agreement failed", e);
    }
  }

  /**
   * HKDF-SHA256 (Extract-then-Expand) as defined in RFC 5869.
   * Implements the N=1 case used by the protocol.
   *
   * @param salt   the salt (32 bytes)
   * @param ikm    the input keying material (shared secret)
   * @param info   the context and application specific information
   * @param length the length of the output keying material
   * @return the derived key material
   */
  private byte[] hkdfExpand(byte[] salt, byte[] ikm, byte[] info, short length) {
    try {
      // Extract: PRK = HMAC-SHA256(salt, IKM)
      javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(salt, "HmacSHA256"));
      byte[] prk = mac.doFinal(ikm);

      // Expand: OKM = HKDF-Expand(PRK, info, L)
      // T(0) = empty string (no input to MAC)
      // T(1) = HMAC-Hash(PRK, T(0) || info || 0x01)
      mac = javax.crypto.Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(prk, "HmacSHA256"));
      mac.update(info);
      mac.update((byte) 0x01);
      return mac.doFinal();
    } catch (Exception e) {
      throw new RuntimeException("HKDF failed", e);
    }
  }

  /**
   * Encrypts plaintext with AES-128-CCM using the client-to-card key.
   *
   * @param plaintext the data to encrypt
   * @return ciphertext with appended 8-byte tag
   */
  private byte[] encryptCCM(byte[] plaintext) {
    try {
      byte[] nonce = Arrays.copyOf(nonceCounter, CCM_NONCE_SIZE);
      GCMParameterSpec spec = new GCMParameterSpec(CCM_TAG_SIZE * 8, nonce);

      cipherC2H.init(Cipher.ENCRYPT_MODE, keyC2H, spec);
      byte[] ciphertext = cipherC2H.doFinal(plaintext);

      // Increment nonce counter (big-endian)
      incrementNonce();

      return ciphertext; // CCM appends tag automatically
    } catch (Exception e) {
      throw new RuntimeException("AES-CCM encryption failed", e);
    }
  }

  /**
   * Decrypts ciphertext with AES-128-CCM using the card-to-client key.
   *
   * @param ciphertext the data to decrypt (includes appended 8-byte tag)
   * @return the decrypted plaintext
   */
  private byte[] decryptCCM(byte[] ciphertext) {
    try {
      byte[] nonce = Arrays.copyOf(nonceCounter, CCM_NONCE_SIZE);
      GCMParameterSpec spec = new GCMParameterSpec(CCM_TAG_SIZE * 8, nonce);

      cipherH2C.init(Cipher.DECRYPT_MODE, keyH2C, spec);
      return cipherH2C.doFinal(ciphertext);
    } catch (Exception e) {
      open = false;
      throw new RuntimeException("AES-CCM decryption failed", e);
    }
  }

  /**
   * Increments the 13-byte nonce counter as a big-endian integer.
   *
   * @throws RuntimeException on overflow (2^104 would require session reset)
   */
  private void incrementNonce() {
    for (int i = CCM_NONCE_SIZE - 1; i >= 0; i--) {
      nonceCounter[i]++;
      if (nonceCounter[i] != 0) {
        return;
      }
    }
    // Overflow — session must be reset
    open = false;
    throw new RuntimeException("Nonce counter overflow — secure channel session expired");
  }
}
