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






```

```
```

```
```


