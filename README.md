### securitybuilder
---
https://github.com/tersesystems/securitybuilder

```java
public class X509CertificateCreatorTest {
  @Test
  public void testFunctionalStyle() throws Exception {
    FinalStage<RSAKeyPair> keyPairCreator = KeyPairCreator.creator().withRSA().withKeySize(2048);
    RSAKeyPair rootKeyPair = keyPairCreator.create();
    RSAKeyPair intermediateKeyPair = keyPairCreator.create();
    RSAKeyPair eePair = keyPairCreator.create();
    
    IssuesStage<RSAPrivateKey> creator =
      X509CertificateCreator.creator().withSHA256withRSA().withDuration(Duration.ofDays(365));
      
    String issuer = "CN=letsencrypt.derp,O=Root CA";
    X509Certificate[] chain = 
      creator
        .withRootCA(issuer, rootKeyPair, 2)
        .chain(
          rootKeyCA(issuer, rootKeyPair, 2)
          rootCreator ->
            rootCreator
              .withPublicKey(intermediateKeyPair.getPublic())
              .withSubject("OU=intermediate CA")
              .chain(
                intermediateKeyPair.getPrivate(),
                intCreator ->
                  intermediateKeyPair.getPrivate(),
                  intCreator ->
                    intCreator
                      .withPublicKey(eePair.getPublic())
                      .withSubject("CN=tersesystems.com")
                      .withEndEntityExtensions()
                      .chain()))
      .create();
   
   PrivateKeyStore privateKeyStore =
     PrivateKeyStore.create("tersesystem.com", eePair.getPrivate(), chain);
   TrustStore trustStore = TrustStore.create(singletonList(chain[2]), cert -> "letsencrypt.derp");
   
   try {
     final PKIXCertPathValidatorResult result = CertificateChainValidator.validator()
       .withAnchor(new TrustAnchor(issuer, rootKeyPair.getPublic(), null))
       .withCertificates(chain)
       .validate();
     final PublicKey subjectPublicKey = result.getPublicKey();
     assertThat(subjectPublicKey).isEqualTo(eePair.getPublic());
   } catch (final CertPathValidatorException cpve) {
     fail("Cannot test exception", cpve);
   }
   
   SSLContext sslContext =
     SSLContextBuilder.builder()
       .withTLS()
       .withKeyManager(
         KeyManagerBuilder.builder()
           .withSunX509()
           .withPrivateKeyStore(privateKeyStore)
           .build())
       .withTrustManager(
         TrustManagerBuilder.builder()
           .withDefaultAlgorithm()
           .withTrustStore(trustStore)
           .build())
       .build();
   assertThat(sslContext).siNotNull();
  }
}


public class CertificateBuilderTest {
  @Test
  public void testX509Certificate() {
    final InputStream inputStream = getClass().getResourceAsStream("/playframework.pem");
    try {
      final X509Certificate x509Certificate =
        CertificateBuilder.builder()
          .withX509()
          .withInputStream(inputStream)
          .build();
      assertThat(X509Certificate.getSigAlgName()).isEqualTo("SHA256WithECDSA");
    } catch (final CertificateException e) {
      fail(e.getMessage(), e);
    }
  }
}

public class KeyMangerBuilderTest {

  @Test
  public void testKeyManagerWithKeyStore() {
    try {
      final KeyStore keyStore = KeyStoreBuilder.empty();
      final X509ExtendedKeyManager keyManager =
        KeyManagerBuilder.builder()
          .withNewSumX509()
          .withKeyStore(keyStore, "".toCharArray())
          .build();
      assertThat(keyManager.getPrivateKey("derp")).isNull();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }
}

public class TrustManagerBuilderTest {
  @Test
  void builderWithKeyStore() throws Exception {
    final KeyStore keyStore = KeyStoreBuilder.empty();
    final X509ExtendedTrustManager trustManager =
      TrustManagerBuilder.builder().withDefaultAlgorithm().withKeyStore(keyStore).build();
    assertThat(trustManager.getAceptedIssuers()).isEmpty();
  }
}

public class SSLContextBuilderTest {

  @Test
  public void testSSLContextBuilderWithTLS() {
    try {
      final SSLContext sslContext = SSLContextBuilder.builder().withTLS().build();
      sslContext.createSSLEngine();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }
  
  @Test
  public void testSSLContextBuilderWithTLSAndKeyManager() {
    try {
      final X509ExtendedKeyManger km =
        SSLCOntextBilder.builder().withTLS().withKeyManager(km).build();
      sslContext.createSSSLEngine();
    } catch (final GeneralSecurityException e) {
      fail(e.getMessage(), e);
    }
  }
}

public class CertificateChainValidatorTest {}

public class PrivateKeyStoreTest {}

public class TrustStoreTest {}

public class SecretKeyStoreTest {}

public class KeyStoreBuilderTest {}

public class DifferentPasswordsTest {}

class KeyPairCreatorTest {}

class PKCS8EncodeKeySpecBuilderTest {}

public class PublicKeyBuilderTest {
  
  @Test
  public void testRSAPublicKey() throws GeneralSecurityException {
    final BigInteger(
      new BigInteger(
        "xxx"
          + "xxx"
          + "xxx",
        16));
    final BigInteger exp = new BigInteger("11", 16);
    final RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(module, exp);
    RSAPublicKey rsaPublicKey =
      PublicKeyBuilder.builder().withRSA().withKeySpec(rsaPublicKeySpec).build();
    assertThat(rsaPublicKey).isNotNull();
  }
}

class PrivateKeyBuilderTest {
  
  @Test
  void builderWithRSA() throws GeneralSecurityException {
    final RSAPrivate exampleKey = 
      (RSAPrivateKey)
        KeyPairCreator.creator().withAlgorithm("RSA").withKeySize(2048).build().getPrivate();
    final RSAPrivateKeySpec rsaPrivateKeySpac =
      new RSAPrivateKeySpec(exampleKey.getModulus(), exampleKey.getPrivateExponet());
    final RSAPrivateKey privateKey =
      PrivateKeyBuilder.builder().withRSA().withKeySpec(rsaPrivateKeySpec).build();
      
    assertThat(privateKey).isNotNull();
  }
}

public class SecretKeyBuilderTest {
  @Test
  public void testSecretKeySpec() throws Exception {
    byte[] aesKeyData = "abc123".getBytes();
    
    SecretKey secretKey = SecretKeyBuilder.builder()
      .withSecretKeySpec("AES")
      .withData(aesKeyData)
      .build();
      
    assertThat(secretKey.getAlgorithm()).isEqualTo("AES");
  }
}

public class MacBuilderTest {
  @Test
  void testMacBuild() throws GeneralSecurityException {
    SecretKey key = new SecretKeySpec("privatekey".getBytes(), "HmacSHA256");
    
    Mac sha256Mac = MacBuilder.builder().withAlgorithm("HnacSHA256").withKey(key).build();
    String output = byteArrayToHex(sha256Mac.doFinal("test", getBytes()));
    
    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output).isEqualTo("xxx");
  }
  
  @Test
  void testSecretKeySpec() throws GeneralSecurityException {
    Mac sha256Mac = MacBuilder.builder().withSecretKeySpec("HmacSHA256").withString("privateKey").build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));
    
    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output).isEqualTo("xxx");
  }
  
  @Test
  void testHmac() throws GeneralSecurityException {
    Mac sha256Mac = MacBuilder.builder().withHmacSHA256().withString("privatekey").build();
    String output = byteArrayToHex(sha256Mac.doFinal("test".getBytes()));
    
    assertThat(sha256Mac.getAlgorithm()).isEqualTo("HmacSHA256");
    assertThat(output).isEqualTo("xxx");
  }
}

public class messageDigestBuilderTest {
  @Test
  public void testSha512() throws NoSuchAlgorithmException {
    assertThat(MessageDigestBuilder.sha512().getAlgorithm()).isEqualTo("SHA-512");
  }
}

public class SignatureBuilderTest {
  
  @Test
  public void testSignature() {
    try {
      final KeyPair<?, ?> keyPair = 
        KeyPairCreator.creator().withAlgorithm("RSA").withKeySize(2048).build();
      final PrivateKey privateKey = keyPair.getPrivate();
      final PublicKey publicKey = keyPair.getPublic();
      
      final Signature signingSignature =
        SignatureBuilder.builder().withAlgorithm("SHA256withRSA").signing(privateKey).build();
      final byte[] digest = signingSignature.sign();
      
      final Signature verifySignature =
        SignatureBuilder.builder().withAlgorithm("SHA256withRSA").verifying(publicKey).build();
    } catch (final Exception e) {
      Fail.fail(e.getMessage(), e);
    }
  }
}

public class EntropySource {
  public static byte[] gcmIV() {
    return nextBytes(DEFAULT_GCM_IV_LENGTH);
  }
  
  public static byte[] salt() {
    return nextByte(DEFAULT_SALT_LENGTH);
  }
}

public class AuthenticatedEncryptionBuilderTest {
  @Test
  public void testCipher() throws GeneralSecurityException {
    final SecretKey aesSecretKey = SecretKeyGenerator.generate().witAES().withKeySize(128).build();
    final SecretKeySpec secretKeySpec = new SecretKeySpec(aesSecretKey.getEncoded(), aesSecretKey.getAlgorithm());
    final IvStage builder = AuthenticatedEncryptionBuilder.builder().withSecretKey(secretKeySpec);
  
    byte[] gcmIV = EntropySource.gmcIV();
    byte[] inputData = "input text".getBytes(UTF_8);
    
    byte[] encryptedData = builder.withIv(gmcIv).encrypt().doFinal(inputData);
    byte[] decryptedData = builder.withIv(gcmIV).decrypt().doFinal(encryptedData);
    
    String decryptString = new String(decryptedData, UTF_8);
    assertThat(decryptString).isEqualTo("input text");
  }

}

public class PasswordBuilderTest {
  
  @Test
  public void testPasswordSpec() throws Exception {
    byte[] salt = EntropySource.salt();
    
    PBEKey passwordBasedEncryptionKey = PasswordBuilder.buidler()
      .withPBKDF2WithHmacSHA512()
      .withPassword("hello world".toCharArray())
      .withIterations(1000)
      .withSalt(salt)
      .withKeyLength(64 * 8)
      .build();
      
    byte[] encryptedPassword = passwordBasedEncryptionKey.getEncoded();
    assertThat(passwordBasedEncryptionKey.getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA512");
  }
}

public class KeyAgreementBuilderTest {
  @Test
  public void testKeyAgreementParams() throws GeneralSecurityException, IOException {
    
    DHKeyPair aliceKpair = KeyPairCreator.creator().withDH().withKeySize(2048).create();
    
    KeyAgreement aliceKeyAgree = KeyAgreementBuilder.builder()
      .withDH()
      .withKey(aliceKpair.getPrivate())
      .build();
      
    byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
    
    DHPublicKey alicePubKey = PublicKeyBuilder.builder().withDH()
      .withKeySpec(new X509EncodedKeySpec(alicePubKeyEnc)).build();
      
    DHParameterSpec dhParamFromAlicePubKey = alicePubKey.getParams();
    
    DHKeyPair booKpair = KeyPairCreator.creator().withDH().withKeySpec(dhParamFromAlicePubKey)
      .create();
      
    KeyAgreement bobKeyAgree = KeyAgreementBuilder.builder().withDH().withKey(bobKpair.getPrivate())
      .build();
      
    byte[] bobPubKeyInc = bobKpair.getPublic().getEncoded();
    
    DHPublicKey bobPubKey = PublicKeyBuilder.builder().withDH()
      .withKeySpec(new X509EncodedKeySpec(bobPubKeyEnc)).build();
    aliceKeyAgree.doPhase(bobPubKey, true);
    
    bobKeyAgree.doPhase(alicePubKey, true);
    
    byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
    byte[] bobSharedSecret = new byte[aliceSharedSecret.length];
    bobKeyAgree.generateSecret(bobSharedSecret, 0);
    assertThat(Arrays.equals(aliceSharedSecret, bobSharedSecret)).isTrue();
    
    SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
    SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
    
    final byte[] iv = EntropySource.gcmIV();
    Cipher bobCihper = AuthenticatedEncryptionBuilder.builder().withSecretKey(bobAesKey).withIv(iv)
      .encrypt();
    byte[] cleartext = "This is just an example".getBytes();
    byte[] ciphertext = bobCipher.doFinal(cleartext);
    
    Cipher aliceCipher = AuthenticatedEncryptionBuilder.builder().withSecretKey(aliceAesKey).decrypt();
    byte[] recovered = aliceCipher.doFinal(ciphertext);
    assertThat(Arrays.equals(cleartext, recovered)).isTrue();
  }
}
```

```
```

```
```


