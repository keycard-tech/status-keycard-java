package im.status.keycard.applet;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import java.io.IOException;

/**
 * Common interface for Secure Channel implementations.
 *
 * V1 (SecureChannelSession): AES-CBC with CMAC, pairing-based key derivation.
 * V2 (SecureChannelV2Client): ECDHE on secp256k1, HKDF-SHA256, AES-128-CCM.
 */
public interface SecureChannel {

  /**
   * Establishes a Secure Channel with the card, performing the full handshake
   * including mutual authentication (V1) or card authentication (V2).
   *
   * @param apduChannel the APDU channel
   * @throws IOException  communication error
   * @throws APDUException secure channel error
   */
  void autoOpenSecureChannel(CardChannel apduChannel) throws IOException, APDUException;

  /**
   * Performs the pairing procedure (V1 only).
   *
   * @param apduChannel   the APDU channel
   * @param pairingMode   the pairing mode
   * @param sharedSecret  the shared secret
   * @throws IOException             communication error
   * @throws APDUException           pairing error
   * @throws UnsupportedOperationException if called on a V2 channel
   */
  void autoPair(CardChannel apduChannel, byte pairingMode, byte[] sharedSecret)
      throws IOException, APDUException;

  /**
   * Unpairs the current paired key (V1 only).
   *
   * @param apduChannel the APDU channel
   * @throws IOException                   communication error
   * @throws APDUException                 unpairing error
   * @throws UnsupportedOperationException if called on a V2 channel
   */
  void autoUnpair(CardChannel apduChannel) throws IOException, APDUException;

  /**
   * Unpair all other clients (V1 only).
   *
   * @param apduChannel the APDU channel
   * @throws IOException                   communication error
   * @throws APDUException                 unpairing error
   * @throws UnsupportedOperationException if called on a V2 channel
   */
  void unpairOthers(CardChannel apduChannel) throws IOException, APDUException;

  /**
   * Sends an OPEN SECURE CHANNEL APDU.
   *
   * @param apduChannel the APDU channel
   * @param index       the P1 parameter (pairing index for V1, ignored for V2)
   * @param data        the data
   * @return the raw card response
   * @throws IOException communication error
   */
  APDUResponse openSecureChannel(CardChannel apduChannel, byte index, byte[] data)
      throws IOException;

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU (V1 only).
   *
   * @param apduChannel the APDU channel
   * @return the raw card response
   * @throws IOException                   communication error
   * @throws UnsupportedOperationException if called on a V2 channel
   */
  APDUResponse mutuallyAuthenticate(CardChannel apduChannel) throws IOException;

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU (V1 only).
   *
   * @param apduChannel the APDU channel
   * @param data        the data
   * @return the raw card response
   * @throws IOException                   communication error
   * @throws UnsupportedOperationException if called on a V2 channel
   */
  APDUResponse mutuallyAuthenticate(CardChannel apduChannel, byte[] data) throws IOException;

  /**
   * Sends a PAIR APDU (V1 only).
   *
   * @param apduChannel the APDU channel
   * @param p1          the P1 parameter
   * @param p2          the P2 parameter
   * @param data        the data
   * @return the raw card response
   * @throws IOException                   communication error
   * @throws UnsupportedOperationException if called on a V2 channel
   */
  APDUResponse pair(CardChannel apduChannel, byte p1, byte p2, byte[] data) throws IOException;

  /**
   * Sends an UNPAIR APDU (V1 only).
   *
   * @param apduChannel the APDU channel
   * @param p1          the P1 parameter
   * @return the raw card response
   * @throws IOException                   communication error
   * @throws UnsupportedOperationException if called on a V2 channel
   */
  APDUResponse unpair(CardChannel apduChannel, byte p1) throws IOException;

  /**
   * Returns a command APDU with the secure channel wrapper applied.
   *
   * For V1: encrypts the data with AES-CBC and prepends the IV.
   * For V2: wraps the full inner APDU in the secured command format (CLA=0x80, INS=0x18).
   *
   * @param cla  the CLA byte of the inner command
   * @param ins  the INS byte of the inner command
   * @param p1   the P1 byte of the inner command
   * @param p2   the P2 byte of the inner command
   * @param data the data of the inner command
   * @return the wrapped command APDU
   */
  APDUCommand protectedCommand(int cla, int ins, int p1, int p2, byte[] data);

  /**
   * Transmits a protected command APDU and unwraps the response.
   *
   * For V1: verifies the MAC, decrypts the data, extracts the inner SW.
   * For V2: decrypts the AES-CCM payload, extracts the inner APDU data and SW.
   *
   * @param apduChannel the APDU channel
   * @param apdu        the APDU to send
   * @return the unwrapped response APDU (data only, SW from inner payload)
   * @throws IOException transmission error
   */
  APDUResponse transmit(CardChannel apduChannel, APDUCommand apdu) throws IOException;

  /**
   * Returns the current pairing data (V1 only).
   *
   * @return the pairing, or null for V2
   */
  Pairing getPairing();

  /**
   * Sets the pairing data (V1 only). No-op for V2.
   *
   * @param pairing the pairing data
   */
  void setPairing(Pairing pairing);

  /**
   * Resets the secure channel, invalidating the current session.
   */
  void reset();
}
