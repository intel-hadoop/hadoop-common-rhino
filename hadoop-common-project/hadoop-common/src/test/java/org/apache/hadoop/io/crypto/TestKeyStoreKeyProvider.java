/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.io.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.URI;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.junit.Test;

/**
 * A test for MRAsyncDiskService.
 */
public class TestKeyStoreKeyProvider extends TestCase {

  static final URI LOCAL_FS = URI.create("file:///");
  private static Path testDir = new Path(
      System.getProperty("test.build.data", "/tmp"), "test-keystore-keyprovider");
  
  private static final String CRT_KEY_HEAD = "-----BEGIN CERTIFICATE-----";
  private static final String CRT_KEY_TAIL = "-----END CERTIFICATE-----";
  private static final String PRIVATE_KEY_HEAD = "-----BEGIN PRIVATE KEY-----";
  private static final String PRIVATE_KEY_TAIL = "-----END PRIVATE KEY-----";
  private static final String X509KEY_INSTANCE = "X.509";
  private static final String KEY_FACTORY_INSTANCE = "RSA"; 

  private static final String TEST_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
      "MIID4TCCAsmgAwIBAgIJAK3szy3S2rd3MA0GCSqGSIb3DQEBBQUAMIGGMQswCQYD\n" +
      "VQQGEwJDTjERMA8GA1UECAwIU0hBTkdIQUkxDTALBgNVBAcMBENJVFkxDjAMBgNV\n" +
      "BAoMBUlOVEVMMQwwCgYDVQQLDANTU0cxEDAOBgNVBAMMB0hBSUZFTkcxJTAjBgkq\n" +
      "hkiG9w0BCQEWFkhBSUZFTkcuQ0hFTkBJTlRFTC5DT00wHhcNMTExMDA4MDQzNjU2\n" +
      "WhcNMTQwNzA0MDQzNjU2WjCBhjELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNIQU5H\n" +
      "SEFJMQ0wCwYDVQQHDARDSVRZMQ4wDAYDVQQKDAVJTlRFTDEMMAoGA1UECwwDU1NH\n" +
      "MRAwDgYDVQQDDAdIQUlGRU5HMSUwIwYJKoZIhvcNAQkBFhZIQUlGRU5HLkNIRU5A\n" +
      "SU5URUwuQ09NMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArWsqx5fh\n" +
      "8wrBC0Qk3Swuslf2Bj4DYEXJtfTxYqBgtIRYnkZpTLva7NNirrlmI9gtm36T6lHs\n" +
      "Bk5z3e8+jQIO7MopgtfxgWWnQaAFSa9ROSOr7oHCroEloRFajCaUfFajn1uc06i3\n" +
      "E7di3YK+jpGGBaBCHs4Uq7AwNn8IvAdOSc1kiWsP7Vis+TsPRg1xK4ScJfWjrROb\n" +
      "3ySypt08yJYYp0fIemDnHgTzoy+hnO/CUDaTd8M7nCDSHdFtgt2/OBibKokDj+br\n" +
      "yb0E3aIAMhhhj93Im67Gtvjqu/KW3s0gjNKALfpYF9j8p0xX4A/uPNo3kx0FEN+m\n" +
      "hddcJmuZ+MAN8QIDAQABo1AwTjAdBgNVHQ4EFgQUOIFpTzrnXP/mYx+e7KcjTAuK\n" +
      "hI0wHwYDVR0jBBgwFoAUOIFpTzrnXP/mYx+e7KcjTAuKhI0wDAYDVR0TBAUwAwEB\n" +
      "/zANBgkqhkiG9w0BAQUFAAOCAQEAOSi7AxfWLTrxY77m+STXckjTOnyIiL8EAcPH\n" +
      "teUuuVddiParUImTTb5dxkOvwo1k3EKNlFh6LR0JIS5oqv/vBj5kZYs/mrWygbgW\n" +
      "NVuquJSK3OzvW4nepp/9qJyf8UJKt+VeeTWMYJ7HqsS0+N/j0VuWp8HaUuifspCJ\n" +
      "HGihe13Dlusu2IO2SsV1EiDwUZZ2nccKClIdoIciroo1GJ+jG9vD1QUXVxw8g9tl\n" +
      "doi/lYkozLsMNidot7i/b4GAVl+y75Vde9hlzidnvoDYuN9up/XKN8aAGON+sb5f\n" +
      "M5lXDyEltOL32xUKMQU0U4r9lph3DvMFdLqEZ12YwM82CZ4/qg==\n" +
      "-----END CERTIFICATE-----";

  private static final String TEST_PRIVATE_KEY= "-----BEGIN PRIVATE KEY-----\n" +
      "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCtayrHl+HzCsEL\n" +
      "RCTdLC6yV/YGPgNgRcm19PFioGC0hFieRmlMu9rs02KuuWYj2C2bfpPqUewGTnPd\n" +
      "7z6NAg7syimC1/GBZadBoAVJr1E5I6vugcKugSWhEVqMJpR8VqOfW5zTqLcTt2Ld\n" +
      "gr6OkYYFoEIezhSrsDA2fwi8B05JzWSJaw/tWKz5Ow9GDXErhJwl9aOtE5vfJLKm\n" +
      "3TzIlhinR8h6YOceBPOjL6Gc78JQNpN3wzucINId0W2C3b84GJsqiQOP5uvJvQTd\n" +
      "ogAyGGGP3cibrsa2+Oq78pbezSCM0oAt+lgX2PynTFfgD+482jeTHQUQ36aF11wm\n" +
      "a5n4wA3xAgMBAAECggEABW9kadkCxeFCZ539IclutTw4g72R0YSea8t/fT3VihLT\n" +
      "zDIcvsDsfZuqbht1bg4qb8Mp06A5q4Dt9Li41yaHXTiA0I8ADLQo58+iGssZ2paZ\n" +
      "nuIGPf3iNggbNGVJJhR5EFeItMGG62FGAfdFDabV8nsxV1HSKAdfm3WjynDYLUvr\n" +
      "c4A7PV30E16JXElASCueqfUbWUKtYGKg1mENQYEjRoZRd8ttauaszzbw52s6hY+6\n" +
      "sL/voZrU8v9sn2b44u3s7qk2b0TkA6VuoqELD9Ce9uc8qHvo4WSFOU6rYEIkskAa\n" +
      "mw4wv2hFcA5uBmjB2ze3yJg2Z2BSKBPa7uf34I9UoQKBgQDUimVrGx7FkEu0bOYH\n" +
      "XygrpZpwSUh/IhuoCloxzU32vRJSg6ZAqpx/gTQJFpwGbRZXyYuTRlvBtlYDbKIA\n" +
      "LKR7UmPg014NRnLtZl+e6KqX4NN3KlAezaTlBryFmUL+7Uz0dSv8ZT/4HRQCN4Ea\n" +
      "TfYAV4TEqgHxPvZ92HjUxMHotQKBgQDQ4OZkj0XwOAB2qfc7wWfNSEyUjynBX47/\n" +
      "BPg+wqYCjIi3wcW3XDbikq8OIppI4Bp38bEBId0sl8s6X5G1VeJRoAqTmHmA+EQS\n" +
      "+KucQb20zey1rx4snCEYLN+8J6/mvxRFSIkV88eGni2bGaD90EjLwjNsE0U2mSLM\n" +
      "gu4vk1ABzQKBgQCyomc/MBoa3n5idKyZQYcXuCYnfdBq2hX4lEreVLnUSXEe3Ptc\n" +
      "mojSOZusj84vMHx46DJhY9823rNISYOXNe5AoCzGB6Ci87UghsyTWOYYpKPXIj8Y\n" +
      "xKp0u8azWu8OKBBn3htMFSVAud/ZRSFDJIdAHk6+pEzhoJO3jbtwyLZZiQKBgQC3\n" +
      "RCxBHMfzTV9yvgvS3Q2TOpUeX0H2jT4smJKqliQL5nvqJlSwXXM2dharo0aVHDN8\n" +
      "+40e/jRNdN112PZCERmiHnZJK6Wnt6warR382l11Lpw6iGxEHbSXvn+LWZLnNM23\n" +
      "QD4vCZYNkelXxTPQnhfQ1xJBB+NZVSEIKPSMv4aaHQKBgQCeWwJb9cV+monoYUSb\n" +
      "DL4mKSgEttynTRCN19an8pDZAsKVLo1qbAUWE5n70od9E1PLqKTXa4VRk2JsFxpq\n" +
      "b4haYgVEnMiZB0ImD84DdkQFzhkrj5ndtEbKHgWQ2dgdOZ1zF6+8hkfgYcZdXEyf\n" +
      "NEOybLjrD7iAjmbbjhD00PWJmw==\n" +
      "-----END PRIVATE KEY-----";

  @Override
  protected void setUp() throws Exception {

  }

  /**
   * This test check shared passwords for key store and kes.  
   */
  @Test(timeout=15000)
  public void testSharedPasswordJCEKS() throws Throwable {
    testSharedPassword("JCEKS");
  }

  /**
   * This test check separately passwords for key store and keys.  
   */
  @Test(timeout=15000)
  public void testUnsharedPasswordJCEKS() throws Throwable {
    testUnsharedPassword("JCEKS");
  }
  
  /**
   * This test check shared passwords for key store and kes.  
   */
  @Test(timeout=15000)
  public void testKeyStoreJKS() throws Throwable {
    Configuration conf = new Configuration();

    String keyStoreType = "JKS";
    String keyStoreFile = "file:///" + testDir + "/unsharedpassword.keystore";
    String keyStorePassword = "12345678";
    String keyPassword = "87654321";
    String keyStorePasswordFile = "file:///" + testDir + "/unsharedpassword.keystore.passwords";
    
    String publicKeyStoreFile = "file:///" + testDir + "/public.keystore";
    String privateKeyStoreFile = "file:///" + testDir + "/private.keystore";
    String publicKeyStorePassword = "public123";
    String privateKeyStorePassword = "private123";
    String publicKeyName = "PUBLICKEY1";
    String privateKeyName = "PRIVATEKEY1";
    
    createUnsharedPasswordKeyStoreJKS();
    createPublicKeyStore(publicKeyStoreFile, keyStoreType);
    createPrivateKeyStore(privateKeyStoreFile, keyStoreType);
 
    String keyProviderParameters = 
        KeyStoreKeyProvider.getKeyStoreParameterString(
            keyStoreFile, keyStoreType, keyStorePassword, keyStorePasswordFile, false);

    String keyProviderPublicKeyParameters = 
        KeyStoreKeyProvider.getKeyStoreParameterString(
            publicKeyStoreFile, keyStoreType, publicKeyStorePassword, null, true);

    String keyProviderPrivateKeyParameters = 
        KeyStoreKeyProvider.getKeyStoreParameterString(
            privateKeyStoreFile, keyStoreType, privateKeyStorePassword, null, true);
    
    KeyStoreKeyProvider keyProvider = new KeyStoreKeyProvider();
    keyProvider.setConf(conf);
    keyProvider.init(keyProviderParameters);
    
    String[] keyNames = new String[] {"KEY00", "KEY01", "KEY02"};
    Key[] keys = keyProvider.getKeys(keyNames);
    assertTrue("Not all the keys are retrieved", keys.length == keyNames.length);
    
    for(int i = 0; i < keyNames.length; i++) {
      Key key = keys[i];
      assertTrue(key.equals(getNonsymmetricKey(keyStoreFile, keyStoreType, 
          keyStorePassword, keyNames[i], keyPassword)));
    }
    
    KeyStoreKeyProvider keyProviderPublicKey = new KeyStoreKeyProvider();
    keyProviderPublicKey.setConf(conf);
    keyProviderPublicKey.init(keyProviderPublicKeyParameters);
    
    String[] publicKeyNames = new String[] {publicKeyName};
    Key[] publicKeys = keyProviderPublicKey.getKeys(publicKeyNames);
    assertTrue("Not all the keys are retrieved", publicKeys.length == publicKeyNames.length);
    
    for(int i = 0; i < publicKeyNames.length; i++) {
      Key key = publicKeys[i];
      assertTrue(key.equals(getKey(publicKeyStoreFile, keyStoreType, 
          publicKeyStorePassword, publicKeyNames[i], publicKeyStorePassword)));
    }
    
    KeyStoreKeyProvider keyProviderPrivateKey = new KeyStoreKeyProvider();
    keyProviderPrivateKey.setConf(conf);
    keyProviderPrivateKey.init(keyProviderPrivateKeyParameters);
    
    String[] privateKeyNames = new String[] {privateKeyName};
    Key[] privateKeys = keyProviderPrivateKey.getKeys(privateKeyNames);
    assertTrue("Not all the keys are retrieved", privateKeys.length == privateKeyNames.length);
    
    for(int i = 0; i < privateKeyNames.length; i++) {
      Key key = privateKeys[i];
      assertTrue(key.equals(getKey(privateKeyStoreFile, keyStoreType, 
          privateKeyStorePassword, privateKeyNames[i], privateKeyStorePassword)));
    }
  }

  @Test(timeout=15000)
  public void testSharedPassword(String keyStoreType) throws Throwable {
    Configuration conf = new Configuration();
    createSharedPasswordKeyStore(keyStoreType);
    
    String keyStoreFile = "file:///" + testDir + "/sharedpassword.keystore";
    String keyStorePassword = "12345678";
    
    String keyProviderParameters = 
        KeyStoreKeyProvider.getKeyStoreParameterString(
            keyStoreFile, keyStoreType, keyStorePassword, null, true);
    
    KeyStoreKeyProvider keyProvider = new KeyStoreKeyProvider();
    keyProvider.setConf(conf);
    keyProvider.init(keyProviderParameters);

    String[] keyNames = new String[] {"KEY00", "KEY01", "KEY02"};
    Key[] keys = keyProvider.getKeys(keyNames);
    assertTrue("Not all the keys are retrieved", keys.length == 3);
    
    for(int i = 0; i < keyNames.length; i++) {
      Key key = keys[i];
      assertTrue(key.equals(getSymmetricKey(keyStoreFile, keyStoreType, 
          keyStorePassword, keyNames[i], keyStorePassword)));
    }
  }
  
  @Test(timeout=15000)
  public void testUnsharedPassword(String keyStoreType) throws Throwable {
    Configuration conf = new Configuration();
    createUnsharedPasswordKeyStore(keyStoreType);

    String keyStoreFile = "file:///" + testDir + "/unsharedpassword.keystore";
    String keyStorePassword = "12345678";
    String keyPassword = "87654321";
    String keyStorePasswordFile = "file:///" + testDir + "/unsharedpassword.keystore.passwords";

    String keyProviderParameters = 
        KeyStoreKeyProvider.getKeyStoreParameterString(
            keyStoreFile, keyStoreType, keyStorePassword, keyStorePasswordFile, false);
    
    KeyStoreKeyProvider keyProvider = new KeyStoreKeyProvider();
    keyProvider.setConf(conf);
    keyProvider.init(keyProviderParameters);

    String[] keyNames = new String[] {"KEY00", "KEY01", "KEY02"};
    Key[] keys = keyProvider.getKeys(keyNames);
    assertTrue("Not all the keys are retrieved", keys.length == 3);
    
    for(int i = 0; i < keyNames.length; i++) {
      Key key = keys[i];
      assertTrue(key.equals(getSymmetricKey(keyStoreFile, keyStoreType, 
          keyStorePassword, keyNames[i], keyPassword)));
    }
  }


  private void createSharedPasswordKeyStore(String keyStoreType) throws Exception {
    KeyStore ks = KeyStore.getInstance(keyStoreType);

    // get user password and file input stream
    String passphase = "12345678";
    char[] password = passphase.toCharArray();

    ks.load(null, password);

    createSymmetricKey(ks, "KEY00", password);
    createSymmetricKey(ks, "KEY01", password);
    createSymmetricKey(ks, "KEY02", password);

    // store away the keystore
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());
    Path keyStorePath = new Path(testDir, "sharedpassword.keystore");

    if(localfs.exists(keyStorePath))
      localfs.delete(keyStorePath, true);

    localfs.mkdirs(testDir);

    OutputStream os = localfs.create(keyStorePath);
    ks.store(os, password);
    os.close();
  }

  private void createUnsharedPasswordKeyStore(String keyStoreType) throws Exception {
    KeyStore ks = KeyStore.getInstance(keyStoreType);

    // get user password and file input stream
    String passphase = "12345678";
    char[] password = passphase.toCharArray();

    ks.load(null, password);

    String passphasekey = "87654321";
    char[] passwordkey = passphasekey.toCharArray();

    createSymmetricKey(ks, "KEY00", passwordkey);
    createSymmetricKey(ks, "KEY01", passwordkey);
    createSymmetricKey(ks, "KEY02", passwordkey);

    // store away the keystore
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());
    localfs.mkdirs(testDir);


    Path keyStorePath = new Path(testDir, "unsharedpassword.keystore");

    if(localfs.exists(keyStorePath))
      localfs.delete(keyStorePath, true);

    OutputStream os = localfs.create(keyStorePath);
    ks.store(os, password);
    os.close();

    //save properties
    Properties passwords = new Properties();

    passwords.setProperty("KEY00" + KeyStoreKeyProvider.PASSWORD_PROPERTY_SUFFIX, passphasekey);
    passwords.setProperty("KEY01" + KeyStoreKeyProvider.PASSWORD_PROPERTY_SUFFIX, passphasekey);
    passwords.setProperty("KEY02" + KeyStoreKeyProvider.PASSWORD_PROPERTY_SUFFIX, passphasekey);

    Path keyStorePasswordFile = new Path(testDir, "unsharedpassword.keystore.passwords");

    if(localfs.exists(keyStorePasswordFile))
      localfs.delete(keyStorePasswordFile, true);

    OutputStream osp = localfs.create(keyStorePasswordFile);
    passwords.store(osp, "passwords for keys");
    osp.close();
  }
  
  private void createUnsharedPasswordKeyStoreJKS() throws Exception{
    KeyStore ks = KeyStore.getInstance("JKS");

    // get user password and file input stream
    String passphase = "12345678";
    char[] password = passphase.toCharArray();

    ks.load(null, password);

    String passphasekey = "87654321";
    char[] passwordkey = passphasekey.toCharArray();

    createNosymmetricKey(ks, "KEY00", 512, passwordkey);
    createNosymmetricKey(ks, "KEY01", 512, passwordkey);
    createNosymmetricKey(ks, "KEY02", 512, passwordkey);

    // store away the keystore
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());
    localfs.mkdirs(testDir);

    Path keyStorePath = new Path(testDir, "unsharedpassword.keystore");

    if(localfs.exists(keyStorePath))
      localfs.delete(keyStorePath, true);

    OutputStream os = localfs.create(keyStorePath);
    ks.store(os, password);
    os.close();

    //save properties
    Properties passwords = new Properties();

    passwords.setProperty("KEY00" + KeyStoreKeyProvider.PASSWORD_PROPERTY_SUFFIX, passphasekey);
    passwords.setProperty("KEY01" + KeyStoreKeyProvider.PASSWORD_PROPERTY_SUFFIX, passphasekey);
    passwords.setProperty("KEY02" + KeyStoreKeyProvider.PASSWORD_PROPERTY_SUFFIX, passphasekey);

    Path keyStorePasswordFile = new Path(testDir, "unsharedpassword.keystore.passwords");

    if(localfs.exists(keyStorePasswordFile))
      localfs.delete(keyStorePasswordFile, true);

    OutputStream osp = localfs.create(keyStorePasswordFile);
    passwords.store(osp, "passwords for keys");
    osp.close(); 
  }
  
  private void createSymmetricKey(KeyStore ks, String keyName, char[] password) throws Exception {
    createSymmetricKey(ks, "AES", 128, keyName, password);
  }

  private void createSymmetricKey(KeyStore ks, String cryptographicAlogrithm, int cryptographicLength, String keyName, char[] password) throws Exception {
    KeyGenerator kgen = KeyGenerator.getInstance(cryptographicAlogrithm);
    kgen.init(cryptographicLength); 

    SecretKey secretKey = kgen.generateKey();

    // save secret key
    KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
    ks.setEntry(keyName, skEntry, new KeyStore.PasswordProtection(password));
  }
  
  private Key getSymmetricKey(String keyStoreFile, String keyStoreType, String keyStorePassword, String keyName, String keyPassword) throws Exception {
    // store away the keystore
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());

    Path keyStorePath = new Path(keyStoreFile);
    KeyStore ks = KeyStore.getInstance(keyStoreType);

    InputStream in = new BufferedInputStream(localfs.open(keyStorePath));
    try {
      ks.load(in, keyStorePassword.toCharArray());
    } finally {
      in.close();
    }

    PasswordProtection protection = null;
    if (keyPassword != null && 
        !keyPassword.isEmpty())
      protection = new PasswordProtection(keyPassword.toCharArray());

    KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry)ks.getEntry(keyName, protection);
    if(skEntry == null)
      throw new Exception("Key with the name not found. Name : " + keyName);

    SecretKey secretKey = skEntry.getSecretKey();
    byte[] rawKey = secretKey.getEncoded();
    return new Key(Key.KeyType.SYMMETRIC_KEY, "AES", 128, secretKey.getFormat(), rawKey);
  }
  
  private Key getKey(String keyStoreFile, String keyStoreType, String keyStorePassword, String keyName, String keyPassword) throws Exception {
    // store away the keystore
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());

    Path keyStorePath = new Path(keyStoreFile);
    KeyStore ks = KeyStore.getInstance(keyStoreType);

    InputStream in = new BufferedInputStream(localfs.open(keyStorePath));
    try {
      ks.load(in, keyStorePassword.toCharArray());
    } finally {
      in.close();
    }
    
    char[] passphase = null;
    if(keyPassword != null && 
        !keyPassword.isEmpty())
      passphase = keyPassword.toCharArray();
    
    Key.KeyType keyType = Key.KeyType.OPAQUE;
    String algorithm = null;
    String format = null;
    byte[] rawKey;
    
    java.security.Key key = ks.getKey(keyName, passphase);
    if(key != null) {
      //secret key or private key
      rawKey = key.getEncoded();
      algorithm = key.getAlgorithm();
      format = key.getFormat();
      
      if(key instanceof SecretKey) {
        keyType = Key.KeyType.SYMMETRIC_KEY;
      } else if(key instanceof PrivateKey) {
        keyType = Key.KeyType.PRIVATE_KEY;
      }
    } else {
      //trusted certificate
      Certificate certificate = ks.getCertificate(keyName);
      if(certificate == null)
        throw new CryptoException ("Key " + keyName + " not found");
      
      keyType = Key.KeyType.CERTIFICATE;
      rawKey = certificate.getEncoded();
    }

    return new Key (keyType, algorithm, 0, format, rawKey);
  }
  
  public void createNosymmetricKey(KeyStore ks, String keyName, int cryptographicLength, char[] password) throws Exception {
    KeyPairGenerator kgen = KeyPairGenerator.getInstance("RSA");
    kgen.initialize(cryptographicLength);

    PrivateKey privateKey = kgen.generateKeyPair().getPrivate();
    Certificate certificate = getCertificate(TEST_CERTIFICATE);
    KeyStore.PrivateKeyEntry skEntry = new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate});
    ks.setEntry(keyName, skEntry, new KeyStore.PasswordProtection(password));
  }
  
  private Key getNonsymmetricKey(String keyStoreFile, String keyStoreType, String keyStorePassword, String keyName, String keyPassword) throws Exception {
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());

    Path keyStorePath = new Path(keyStoreFile);
    KeyStore ks = KeyStore.getInstance(keyStoreType);

    InputStream in = new BufferedInputStream(localfs.open(keyStorePath));
    try{
      ks.load(in, keyStorePassword.toCharArray());
    } finally {
      in.close();
    }

    PasswordProtection protection = null;
    if(keyPassword != null && !keyPassword.isEmpty()) {
      protection = new PasswordProtection(keyPassword.toCharArray());
    }

    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)ks.getEntry(keyName, protection);
    if(privateKeyEntry == null) {
      throw new Exception("Key with the name not found.Name :" + keyName);
    }

    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    byte[] rawKey = privateKey.getEncoded();
    return new Key(Key.KeyType.PRIVATE_KEY, "RAS", 512, privateKey.getFormat(), rawKey);
  }

  public static X509Certificate getCertificate(InputStream is) 
      throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance(X509KEY_INSTANCE);
    X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(is);
    return x509Cert;
  }

  public static X509Certificate getCertificate(String fileContent) 
      throws CertificateException, IOException {
    if (!fileContent.contains(CRT_KEY_HEAD) || 
        !fileContent.contains(CRT_KEY_TAIL))
      throw new CertificateException("Invalid certifcate format.");

    ByteArrayInputStream bin = new ByteArrayInputStream(fileContent.getBytes());
    try {
      return getCertificate(bin);
    } finally {
      bin.close();
    }
  }

  private static String getPrivateKeyContent(BufferedReader in) throws IOException {
    String line;
    StringBuffer privateKeyCont = new StringBuffer("");

    line = in.readLine();
    while (line != null) {
      privateKeyCont.append(line).append("\r\n");
      line = in.readLine();
    }

    String privateKeyString = privateKeyCont.toString();
    privateKeyString = privateKeyString.replace(PRIVATE_KEY_HEAD, "");
    privateKeyString = privateKeyString.replace(PRIVATE_KEY_TAIL, "");
    privateKeyString = privateKeyString.trim();

    return privateKeyString;
  }

  /**
   * The private key string must not contain PRIVATE_KEY_HEAD and PRIVATE_KEY_TAIL
   * @param keyString
   * @return
   */
  public static PrivateKey getPrivateKeyFromContent(String keyString) throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance(KEY_FACTORY_INSTANCE);
    byte [] binaryKey = Base64.decodeBase64(keyString);
    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(binaryKey);
    PrivateKey privateKey = keyFactory.generatePrivate(privSpec);
    return privateKey;
  }

  public static PrivateKey getPrivateKey(String fileContent) 
      throws Exception {
    BufferedReader in = new BufferedReader(new StringReader(fileContent));
    String privateKeyString = getPrivateKeyContent(in);
    in.close();

    return getPrivateKeyFromContent(privateKeyString);
  }

  private void createPublicKeyStore(String publicKeyStore,String keyStoreType) throws Exception {
    KeyStore ks = KeyStore.getInstance(keyStoreType);

    // get user password and file input stream
    String passphase = "public123";
    char[] password = passphase.toCharArray();

    ks.load(null, password);

    createPublicKey(ks, "PUBLICKEY1", password);

    // store away the keystore
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());
    localfs.mkdirs(testDir);


    Path keyStorePath = new Path(publicKeyStore);

    if(localfs.exists(keyStorePath))
      localfs.delete(keyStorePath, true);

    OutputStream os = localfs.create(keyStorePath);
    ks.store(os, password);
    os.close();
  }

  private void createPrivateKeyStore(String keyStoreFile,String keyStoreType) throws Exception {
    KeyStore ks = KeyStore.getInstance(keyStoreType);

    // get user password and file input stream
    String passphase = "private123";
    char[] password = passphase.toCharArray();

    ks.load(null, password);

    createPrivateKey(ks, "PRIVATEKEY1", password);

    // store away the keystore
    FileSystem localfs = FileSystem.get(LOCAL_FS, new Configuration());
    localfs.mkdirs(testDir);


    Path keyStorePath = new Path(keyStoreFile);

    if(localfs.exists(keyStorePath))
      localfs.delete(keyStorePath, true);

    OutputStream os = localfs.create(keyStorePath);
    ks.store(os, password);
    os.close();
  }

  /**
   * Generate key which contains a pair of privae and public key using 1024 bytes
   * @return key pair
   * @throws NoSuchAlgorithmException
   */
  public static KeyPair generateKey() throws NoSuchAlgorithmException
  {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(1024);
    KeyPair key = keyGen.generateKeyPair();
    return key;
  }

  private void createPublicKey(KeyStore ks, String keyName, char[] password) throws Exception {
    Certificate certificate = getCertificate(TEST_CERTIFICATE);
    ks.setCertificateEntry(keyName, certificate);
  }

  private void createPrivateKey(KeyStore ks, String keyName, char[] password) throws Exception {
    PrivateKey privateKey = getPrivateKey(TEST_PRIVATE_KEY);
    Certificate certificate = getCertificate(TEST_CERTIFICATE);

    ks.setKeyEntry(keyName, privateKey, password, new Certificate[]{certificate});
  }
}
