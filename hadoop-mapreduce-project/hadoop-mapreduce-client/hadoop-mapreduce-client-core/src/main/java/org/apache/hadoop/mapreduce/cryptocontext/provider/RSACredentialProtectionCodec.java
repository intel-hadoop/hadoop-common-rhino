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

package org.apache.hadoop.mapreduce.cryptocontext.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.crypto.CryptoCodec;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.Key.KeyType;
import org.apache.hadoop.io.crypto.aes.AESCodec;

/**
 * <code>RSACredentialProtectionCodec</code> is a built-in implementation of asymmetric {@link CryptoCodec}
 * using RSA asymmetric algorithm.
 * Internally, AES is used to encrypt and decrypt the real data and RSA is used to encrypt and decrypt to AES
 * key which is generated at random and the encrypted key is stored with the encrypted data.
 */
public class RSACredentialProtectionCodec implements CryptoCodec, Configurable {
  private Configuration conf;
  private CryptoContext cryptoContext;

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out)
      throws IOException {
    return new CompressionOutputStream(out){
      private ByteArrayOutputStream bufStream = new ByteArrayOutputStream(1024);
      private int bufLen = 0;
      private boolean finish = false;

      @Override
      public void write(byte[] b, int off, int len) throws IOException {
        if (b == null) {
          throw new NullPointerException();
        } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length)) {
          throw new IndexOutOfBoundsException();
        } else if (len == 0) {
          return;
        }

        bufStream.write(b, off, len);
        bufLen += len;
      }

      @Override
      public void finish() throws IOException {
        if(!finish){
          finish = true;

          if(cryptoContext == null)
            throw new IOException("Crypto context can't be null.");

          Key key = cryptoContext.getKey();
          if(key == null)
            throw new IOException("The key is not specified for encryption.");

          try{
            byte[] encrypted = encryptData(bufStream.toByteArray(), 0, bufLen, key, getConf());
            out.write(encrypted);

          } catch (Exception e){
            throw new IOException(e);
          }
        }
      }

      @Override
      public void resetState() throws IOException {
        bufStream.reset();
        bufLen = 0;
        finish = false;
      }

      @Override
      public void write(int b) throws IOException {
        throw new IOException("Unsupported operation.");
      }
    };
  }

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out,
      Compressor compressor) throws IOException {
    return createOutputStream(out);
  }

  @Override
  public Class<? extends Compressor> getCompressorType() {
    return null;
  }

  @Override
  public Compressor createCompressor() {
    return null;
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in)
      throws IOException {
    return new CompressionInputStream(in){
      private byte[] buf = null;
      private int bufOff = 0;
      private int bufLen = 0;

      @Override
      public int read(byte[] b, int off, int len) throws IOException {
        if (b == null) {
          throw new NullPointerException();
        } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length)) {
          throw new IndexOutOfBoundsException();
        } else if (len == 0) {
          return 0;
        }

        if(bufLen == 0){
          if(cryptoContext == null){
            throw new IOException("Crypto context can't be null");
          }

          byte[] encrypted = new byte[1024];
          int encryptedLen = 0;
          ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream(1024);
          int n = 0;
          while((n = in.read(encrypted)) > -1){
            encryptedStream.write(encrypted, 0, n);
            encryptedLen += n;
          }
          encrypted = encryptedStream.toByteArray();

          if(encryptedLen > 0){
            try{
              Key key = cryptoContext.getKey();

              if(key == null)
                throw new IOException("The key is not specified for decryption.");

              buf = decryptData(encrypted, 0, encryptedLen, key, getConf());
              bufOff = 0;
              bufLen = buf.length;
            } catch (Exception e){
              throw new IOException(e);
            }
          }
        }

        if(bufLen - bufOff <= 0){
          return -1;
        }

        int read = Math.min(len, bufLen - bufOff);
        System.arraycopy(buf, bufOff, b, off, read);
        bufOff += read;

        return read;
      }

      @Override
      public void resetState() throws IOException {
        buf = null;
        bufOff = 0;
        bufLen = 0;
      }

      @Override
      public int read() throws IOException {
        throw new IOException("Unsupported operation.");
      }

    };
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in,
      Decompressor decompressor) throws IOException {
    return createInputStream(in);
  }

  @Override
  public Class<? extends Decompressor> getDecompressorType() {
    return null;
  }

  @Override
  public Decompressor createDecompressor() {
    return null;
  }

  @Override
  public String getDefaultExtension() {
    return null;
  }

  @Override
  public void setConf(Configuration conf) {
    this.conf = conf;
  }

  @Override
  public Configuration getConf() {
    return conf;
  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {
    this.cryptoContext = cryptoContext;
  }

  @Override
  public CryptoContext getCryptoContext() {
    return cryptoContext;
  }

  protected static byte[] encryptData(byte[] data, int offset, int length, Key key, Configuration conf) throws CryptoException {
    //the raw key must be a public key or certificate
    PublicKey publicKey = null;

    KeyType keyType = key.getKeyType();
    if(keyType == KeyType.PUBLIC_KEY) {
      publicKey = getPublicKey(key.getRawKey());
    } else if(keyType == KeyType.CERTIFICATE) {
      publicKey = getPublicKeyOfCertificate(key.getRawKey());
    } else
      throw new CryptoException("Crendetial encryption key is not a public key or certificate.");

    return encrypt(data, offset, length, publicKey, conf);
  }

  protected static byte[] decryptData(byte[] data, int offset, int length, Key key, Configuration conf) throws CryptoException {
    //the raw key must be a private key
    if(key.getKeyType() != KeyType.PRIVATE_KEY)
      throw new CryptoException("Crendetial decryption key is not a private key.");

    PrivateKey privateKey = getPrivateKey(key.getRawKey());
    return decrypt(data, offset, length, privateKey, conf);
  }

  protected static PublicKey getPublicKey(byte[] rawKey) throws CryptoException {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(rawKey);
      PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
      return publicKey;
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch (InvalidKeySpecException e) {
      throw new CryptoException(e);
    }
  }

  protected static PublicKey getPublicKeyOfCertificate(byte[] rawKey) throws CryptoException {
    ByteArrayInputStream is = new ByteArrayInputStream(rawKey);
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(is);
      return x509Cert.getPublicKey();
    } catch(CertificateException e) {
      throw new CryptoException(e);
    } finally {
      try {
        is.close();
      } catch(IOException e) {
        throw new CryptoException(e);
      }
    }
  }

  protected static PrivateKey getPrivateKey(byte[] rawKey) throws CryptoException {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(rawKey);
      PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
      return privateKey;
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch (InvalidKeySpecException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Encrypt a data using a random symmetric key and the key was encrypted by public key
   * @param data The original plain text
   * @param key The public key
   * @return Encrypted text
   * @throws java.lang.CryptoException
   */
  protected static byte[] encrypt(byte[] data, int offset, int length, PublicKey key, Configuration conf) throws CryptoException {
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");     

      // cryptograpphic secure random
      SecureRandom random = new SecureRandom();
      keyGen.init(256, random);

      SecretKey secretKey = keyGen.generateKey();
      byte[] rawKey = secretKey.getEncoded();
      byte[] encryptedKey = encryptRSA(rawKey, key);

      Key symmetricKey  = new Key(Key.KeyType.SYMMETRIC_KEY, Key.AES, 256, rawKey);
      byte[] encryptedData = encryptAES(data, offset, length, symmetricKey, conf);

      //write out
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(os);

      WritableUtils.writeVInt(out, encryptedKey.length);
      out.write(encryptedKey);

      WritableUtils.writeVInt(out, encryptedData.length);
      out.write(encryptedData);

      out.flush();   
      os.close();

      return os.toByteArray();
    } catch(NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch(IOException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Decrypt data using internal symmetric key which will be decrypted by private key
   * @param data The encrypted data
   * @param key The private key
   * @return The decrypted data
   * @throws java.lang.CryptoException
   */
  protected static byte[] decrypt(byte[] data, int offset, int length, PrivateKey key, Configuration conf) throws CryptoException 
  {
    try {
      ByteArrayInputStream is = new ByteArrayInputStream(data, offset, length);
      DataInputStream in = new DataInputStream(is);

      //read the key
      int len = WritableUtils.readVInt(in);
      byte[] encryptedKey = new byte[len];
      in.readFully(encryptedKey);

      len = WritableUtils.readVInt(in);
      byte[] encryptedData = new byte[len];
      in.readFully(encryptedData);

      byte[] rawKey = decryptRSA(encryptedKey, key);

      Key symmetricKey  = new Key(Key.KeyType.SYMMETRIC_KEY, Key.AES, 256, rawKey);
      byte[] decryptedData = decryptAES(encryptedData, 0, len, symmetricKey, conf);
      return decryptedData;
    } catch(IOException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Encrypt a text using key with AES.
   * @param data The original unencrypted data
   * @param key The symmetric key
   * @return Encrypted text
   * @throws java.lang.CryptoException
   */
  protected static byte[] encryptAES(byte[] data, int offset, int length, Key key, Configuration conf) throws CryptoException, IOException {
    AESCodec codec = new AESCodec();
    codec.setConf(conf);

    CryptoContext cryptoContext = new CryptoContext();
    cryptoContext.setKey(key);
    codec.setCryptoContext(cryptoContext);

    ByteArrayOutputStream os = new ByteArrayOutputStream();
    CompressionOutputStream out = codec.createOutputStream(os);

    try {
      out.write(data, offset, length);
      out.flush();
    } finally {
      out.close();
    }

    return os.toByteArray();
  }

  /**
   * Decrypt a text using key with AES.
   * @param data The encrypted data
   * @param key The symmetric key
   * @return Decrypted text
   * @throws java.lang.CryptoException
   */
  protected static byte[] decryptAES(byte[] data, int offset, int length, Key key, Configuration conf) throws CryptoException, IOException {
    AESCodec codec = new AESCodec();
    codec.setConf(conf);

    CryptoContext cryptoContext = new CryptoContext();
    cryptoContext.setKey(key);
    codec.setCryptoContext(cryptoContext);

    ByteArrayInputStream is = new ByteArrayInputStream(data, offset, length);
    CompressionInputStream in = codec.createInputStream(is);

    try {
      ByteArrayOutputStream os = new ByteArrayOutputStream();

      byte[] buffer = new byte[1024];
      int r;
      while ( (r = in.read(buffer)) > -1) {
        //write
        os.write(buffer, 0, r);
      }

      return os.toByteArray();
    } finally {
      in.close();
    }
  }

  /**
   * Encrypt a text using public key.
   * @param data The original unencrypted data
   * @param key The public key
   * @return Encrypted text
   * @throws java.lang.Exception
   */
  protected static byte[] encryptRSA(byte[] data, PublicKey key) throws CryptoException
  { 
    try {
      // get an RSA cipher object and print the provider
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); 

      // encrypt the plaintext using the public key
      cipher.init(Cipher.ENCRYPT_MODE, key);

      byte[] encrypted = cipher.doFinal(data);
      return encrypted;
    } catch(Exception e) {
      throw new CryptoException("Error happens while encrypting data.", e);
    }

  }

  /**
   * Decrypt data using private key
   * @param data The encrypted data
   * @param key The private key
   * @return The decrypted data
   * @throws java.lang.Exception
   */
  protected static byte[] decryptRSA(byte[] data, PrivateKey key) throws CryptoException 
  { 
    try {
      // decrypt the text using the private key
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

      cipher.init(Cipher.DECRYPT_MODE, key);

      byte[] decrypted = cipher.doFinal(data);
      return decrypted;
    } catch(Exception e) {
      throw new CryptoException("Error happens while decrypting data.", e);
    }
  }
}
