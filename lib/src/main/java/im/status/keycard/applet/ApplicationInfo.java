package im.status.keycard.applet;

/**
 * Parses the response from a SELECT command. If the card has not yet received the INIT command the isInitializedCard
 * will return false and only the getSecureChannelPubKey method will return a valid value.
 */
public class ApplicationInfo {
  private boolean initializedCard;
  private byte[] instanceUID;
  private byte[] secureChannelPubKey;
  private short appVersion;
  private byte freePairingSlots;
  private byte[] keyUID;
  private byte capabilities;
  private byte[] certData; // V2: 98-byte identity certificate

  public static final byte TLV_APPLICATION_INFO_TEMPLATE = (byte) 0xA4;
  public static final byte TLV_PUB_KEY = (byte) 0x80;
  public static final byte TLV_UID = (byte) 0x8F;
  public static final byte TLV_KEY_UID = (byte) 0x8E;
  public static final byte TLV_CAPABILITIES = (byte) 0x8D;

  static final byte CAPABILITY_SECURE_CHANNEL = (byte) 0x01;
  static final byte CAPABILITY_KEY_MANAGEMENT = (byte) 0x02;
  static final byte CAPABILITY_CREDENTIALS_MANAGEMENT = (byte) 0x04;
  static final byte CAPABILITY_NDEF = (byte) 0x08;
  static final byte CAPABILITY_FACTORY_RESET = (byte) 0x10;

  static final byte CAPABILITIES_ALL = CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT | CAPABILITY_NDEF | CAPABILITY_FACTORY_RESET;

  /**
   * Constructs an object by parsing the TLV data.
   *
   * @param tlvData the raw response data from the card
   * @throws IllegalArgumentException the TLV does not follow the allowed format
   */
  public ApplicationInfo(byte[] tlvData) throws IllegalArgumentException {
    TinyBERTLV tlv = new TinyBERTLV(tlvData);

    int topTag = tlv.readTag();
    tlv.unreadLastTag();

    if (topTag == TLV_PUB_KEY) {
      secureChannelPubKey = tlv.readPrimitive(TLV_PUB_KEY);
      initializedCard = false;
      capabilities = CAPABILITY_CREDENTIALS_MANAGEMENT;

      if (secureChannelPubKey.length > 0) {
        capabilities |= CAPABILITY_SECURE_CHANNEL;
      }

      return;
    }

    tlv.enterConstructed(TLV_APPLICATION_INFO_TEMPLATE);

    // Parse fields conditionally by tag for cross-version compatibility.
    // V4+ applets omit instanceUID, secureChannelPubKey and freePairingSlots.

    // instanceUID (0x8F) - present in V1-V3, absent in V4+
    if (tlv.readTag() == TLV_UID) {
      tlv.unreadLastTag();
      instanceUID = tlv.readPrimitive(TLV_UID);
    }

    // secureChannelPubKey (0x80) - present in V1-V3, absent in V4+
    if (tlv.readTag() == TLV_PUB_KEY) {
      tlv.unreadLastTag();
      secureChannelPubKey = tlv.readPrimitive(TLV_PUB_KEY);
    }

    // appVersion (INTEGER 0x02) - present in all versions
    appVersion = (short) tlv.readInt();

    // freePairingSlots (INTEGER 0x02) - present in V1-V3, absent in V4+
    if (tlv.readTag() == TinyBERTLV.TLV_INT) {
      tlv.unreadLastTag();
      freePairingSlots = (byte) tlv.readInt();
    }

    // keyUID (0x8E) - present in all versions
    keyUID = tlv.readPrimitive(TLV_KEY_UID);

    // capabilities (0x8D) - optional; if absent assume all capabilities
    if (tlv.readTag() != TinyBERTLV.END_OF_TLV) {
      tlv.unreadLastTag();
      capabilities = tlv.readPrimitive(TLV_CAPABILITIES)[0];
    } else {
      capabilities = CAPABILITIES_ALL;
    }

    // Parse optional certificate (V2 identity certificate, TLV tag 0x8A)
    if (tlv.readTag() != TinyBERTLV.END_OF_TLV) {
      tlv.unreadLastTag();
      if (tlv.readTag() == Certificate.TLV_CERT) {
        tlv.unreadLastTag();
        certData = tlv.readPrimitive(Certificate.TLV_CERT);
      }
    }

    initializedCard = true;
  }

  /**
   * Returns if the card is initialized or not. If this method returns false, only the getSecureChannelPubKey method
   * will return a valid value.
   *
   * @return true if initialized, false otherwise
   */
  public boolean isInitializedCard() {
    return initializedCard;
  }

  /**
   * Utility method to discover if the card has a master key.
   *
   * @return true if the card has a master key, false otherwise
   */
  public boolean hasMasterKey() {
    return (keyUID != null) && (keyUID.length != 0);
  }

  /**
   * The instance UID of the applet. This ID never changes for the lifetime of the applet.
   *
   * @return the instance UID
   */
  public byte[] getInstanceUID() {
    return instanceUID;
  }

  /**
   * The public key to be used for secure channel opening. Usually handled internally by the KeycardCommandSet.
   *
   * @return the public key
   */
  public byte[] getSecureChannelPubKey() {
    return secureChannelPubKey;
  }

  /**
   * The application version, encoded as a short. The msb is the major revision number and the lsb is the minor one.
   *
   * @return the application version
   */
  public short getAppVersion() {
    return appVersion;
  }

  /**
   * A formatted application version.
   * @return the string representation of the application version
   */
  public String getAppVersionString() {
    return getAppVersionString(appVersion);
  }

  /**
   * A formatted application version.
   * @return the string representation of the application version
   */
  static String getAppVersionString(short appVersion) {
    return (appVersion >> 8) + "." + (appVersion & 0xff);
  }

  /**
   * The number of remaining pairing slots. If zero is returned, no further pairing is possible.
   * @return the number of remaining pairing slots
   */
  public byte getFreePairingSlots() {
    return freePairingSlots;
  }

  /**
   * The UID of the master key on this card. Changes every time a different master key is stored. It has zero length if
   * no key is on the card.
   *
   * @return the Key UID.
   */
  public byte[] getKeyUID() {
    return keyUID;
  }

  /**
   * Returns the capability descriptor for the device.
   *
   * @return the capability descriptor for the device.
   */
  public byte getCapabilities() {
    return capabilities;
  }

  /**
   * Returns true if the device supports the Secure Channel capability.
   *
   * @return true or false
   */
  public boolean hasSecureChannelCapability() {
    return (capabilities & CAPABILITY_SECURE_CHANNEL) == CAPABILITY_SECURE_CHANNEL;
  }

  /**
   * Returns true if the device supports the Key Management capability.
   *
   * @return true or false
   */
  public boolean hasKeyManagementCapability() {
    return (capabilities & CAPABILITY_KEY_MANAGEMENT) == CAPABILITY_KEY_MANAGEMENT;
  }

  /**
   * Returns true if the device supports the Credentials Management capability.
   *
   * @return true or false
   */
  public boolean hasCredentialsManagementCapability() {
    return (capabilities & CAPABILITY_CREDENTIALS_MANAGEMENT) == CAPABILITY_CREDENTIALS_MANAGEMENT;
  }

  /**
   * Returns true if the device supports the NDEF capability.
   *
   * @return true or false
   */
  public boolean hasNDEFCapability() {
    return (capabilities & CAPABILITY_NDEF) == CAPABILITY_NDEF;
  }

  /**
   * Returns true if the device supports the Factory Reset capability.
   *
   * @return true or false
   */
  public boolean hasFactoryResetCapability() {
    return (capabilities & CAPABILITY_FACTORY_RESET) == CAPABILITY_FACTORY_RESET;
  }

  /**
   * Returns the raw identity certificate data (V2 only).
   *
   * This is the 98-byte certificate: compressed_pubkey(33) || r(32) || s(32) || v(1).
   * Used by {@link SecureChannelV2Client} for card authentication during handshake.
   *
   * @return the certificate data, or null if not present (V1 cards)
   */
  public byte[] getCertData() {
    return certData;
  }
}
