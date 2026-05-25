package im.status.keycard.applet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.Arrays;

public class Certificate extends RecoverableSignature {
  public static final byte TLV_CERT = (byte) 0x8A;

  private byte[] identPriv;
  private byte[] identPub;
  
  public Certificate(byte[] publicKey, boolean compressed, byte[] r, byte[] s, int recId) {
    super(publicKey, compressed,r, s, recId);
  }

  public static KeyPair generateIdentKeyPair() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
      ECGenParameterSpec spec = new ECGenParameterSpec("secp256k1");
      keyPairGenerator.initialize(spec, new SecureRandom());
      return keyPairGenerator.generateKeyPair();
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?");
    }
  }

  public static Certificate createCertificate(KeyPair caPair, KeyPair identKeys) {
    try {
      byte[] pub = ((ECPublicKey) identKeys.getPublic()).getQ().getEncoded(true);

      MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
      byte[] hash = md.digest(pub);

      Signature signer = Signature.getInstance("NONEwithECDSA", "BC");
      signer.initSign(caPair.getPrivate());
      signer.update(hash);
      byte[] sig = signer.sign();

      TinyBERTLV tlv = new TinyBERTLV(sig);
      tlv.enterConstructed(TLV_ECDSA_TEMPLATE);
      byte[] r = toUInt(tlv.readPrimitive(TinyBERTLV.TLV_INT));
      byte[] s = toUInt(tlv.readPrimitive(TinyBERTLV.TLV_INT));      
      Certificate cert = new Certificate(((ECPublicKey)caPair.getPublic()).getQ().getEncoded(true), true, r, s, -1);
      cert.calculateRecID(hash);
      cert.identPriv = toUInt(((ECPrivateKey) identKeys.getPrivate()).getD().toByteArray());
      cert.identPub = pub;

      return cert;
    } catch(IllegalArgumentException e) {
      throw e;
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?");
    }
  }

  public static Certificate generateNewCertificate(KeyPair caPair) {
    return createCertificate(caPair, generateIdentKeyPair());
  }

  public static Certificate fromTLV(byte[] certData) {
    try {
      byte[] pub = Arrays.copyOfRange(certData, 0, 33);
      byte[] r = Arrays.copyOfRange(certData, 33, 65);
      byte[] s = Arrays.copyOfRange(certData, 65, 97);
      int recId = certData[97];

      MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
      byte[] hash = md.digest(pub);
      byte[] caPub = recoverFromSignature(recId, hash, r, s, true);

      Certificate cert = new Certificate(caPub, true, r, s, recId);
      cert.identPub = pub;
  
      return cert;
    } catch(IllegalArgumentException e) {
      throw e;
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?");
    } 
  }

  public static byte[] verifyIdentity(byte[] hash, byte[] tlvData) {
    try {
      TinyBERTLV tlv = new TinyBERTLV(tlvData);
      tlv.enterConstructed(TLV_SIGNATURE_TEMPLATE);
      byte[] certData = tlv.readPrimitive(TLV_CERT);
      Certificate cert = fromTLV(certData);
      byte[] signature = tlv.peekUnread();
      Signature verifier = Signature.getInstance("NONEWithECDSA", "BC");

      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(cert.identPub), ecSpec);
      ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

      verifier.initVerify(cardKey);
      verifier.update(hash);
      
      if (!verifier.verify(signature)) {
        return null;
      }

      return cert.getPublicKey();
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?");
    }     
  }

  /**
   * Returns the card's identity public key (compressed, 33 bytes).
   *
   * @return the compressed identity public key
   */
  public byte[] getIdentPub() {
    return identPub;
  }

  public byte[] toStoreData() {
    if (identPriv == null) {
      throw new IllegalStateException("The private key must be set.");
    }

    ByteArrayOutputStream os = new ByteArrayOutputStream();
    
    try {
      os.write(this.identPub);
      os.write(this.getR());
      os.write(this.getS());
      os.write(this.getRecId());
      os.write(this.identPriv);
    } catch(IOException e) {
      throw new RuntimeException(e);
    }

    return os.toByteArray();
  }
}
