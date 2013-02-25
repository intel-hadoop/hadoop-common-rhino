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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.io.WritableUtils;

/**
 * <code>Key</code> class representing a opaque key (raw key) and other meta attributes
 * such as key type (symmetric key, public key or private key and so on) and
 * optional cryptographic algorithm for the key.
 */
public class Key implements Writable {

  public static final String AES = "AES";
  public static final String RSA = "RSA";
  public static final String DSA = "DSA";
  public static final String ECDSA = "ECDSA";
  public static final String DES = "DES";
  public static final String TRIPLE_DES = "3DES";
  public static final String HMAC_SHA1 = "HMAC_SHA1";
  public static final String HMAC_SHA224 = "HMAC_SHA224";
  public static final String HMAC_SHA256 = "HMAC_SHA256";
  public static final String HMAC_SHA384 = "HMAC_SHA384";
  public static final String HMAC_SHA512 = "HMAC_SHA512";
  public static final String HMAC_MD5 = "HMAC_MD5";
  public static final String DH = "DH";
  public static final String ECDH = "ECDH";
  public static final String ECMQV = "ECMQV";
  public static final String BLOWFISH = "Blowfish";
  public static final String CAMELLIA = "Camellia";
  public static final String CAST5 = "CAST5";
  public static final String IDEA = "IDEA";
  public static final String MARS = "MARS";
  public static final String RC2 = "RC2";
  public static final String RC4 = "RC4";
  public static final String RC5 = "RC5";
  public static final String SKIPJACK = "SKIPJACK";
  public static final String TWOFISH = "Twofish";

  /** The key type that categorize the key as symmetric key, public key
   * private key, certificate or other. 
   */
  public enum KeyType {
    SYMMETRIC_KEY,
    PUBLIC_KEY,
    PRIVATE_KEY,
    CERTIFICATE,
    OPAQUE;
  };

  private KeyType keyType = KeyType.SYMMETRIC_KEY;

  private String cryptographicAlgorithm;
  private int cryptographicLength = 256;
  private String format;

  private byte[] rawKey;

  /** A new key. */
  public Key() {
  }

  /**
   * A new key with given attributes.
   * @param keyType The key type of the key
   * @param cryptographicAlgorithm The cryptographic algorithm that the key is associate to
   * @param cryptographicLength The cryptographic length of the key
   * @param rawKey The raw key data
   */
  public Key(KeyType keyType, String cryptographicAlgorithm, int cryptographicLength, byte[] rawKey) {
    this(keyType, cryptographicAlgorithm, cryptographicLength, null, rawKey);
  }

  /**
   * A new key with given attributes.
   * @param keyType The key type of the key
   * @param cryptographicAlgorithm The cryptographic algorithm that the key is associate to
   * @param cryptographicLength The cryptographic length of the key
   * @param format The format of the raw key data
   * @param rawKey The raw key data
   */
  public Key(KeyType keyType, String cryptographicAlgorithm, int cryptographicLength, String format, byte[] rawKey) {
    this.keyType = keyType;
    this.cryptographicAlgorithm = cryptographicAlgorithm;
    this.cryptographicLength = cryptographicLength;
    this.format = format;
    this.rawKey = rawKey;
  }

  /**
   * Return the key type of the key.
   */
  public KeyType getKeyType() {
    return keyType;
  }

  /**
   * Set the key type of the key.
   * @param keyType The key type of the key
   */
  public void setKeyType(KeyType keyType) {
    this.keyType = keyType;
  }

  /**
   * Return the cryptographic algorithm of the key.
   * This cryptographic algorithm is optional.
   */
  public String getCryptographicAlgorithm() {
    return cryptographicAlgorithm;
  }

  /**
   * Set the cryptographic algorithm of the key.
   */
  public void setCryptographicAlgorithm(String cryptographicAlgorithm) {
    this.cryptographicAlgorithm = cryptographicAlgorithm;
  }

  /**
   * Return the cryptographic length of the key.
   * The cryptographic length is optional.
   */
  public int getCryptographicLength() {
    return cryptographicLength;
  }

  /**
   * Set the cryptographic length of the key.
   */
  public void setCryptographicLength(int cryptographicLength) {
    this.cryptographicLength = cryptographicLength;
  }

  /**
   * Return the format of the raw key data.
   * The format attribute is optional.
   */
  public String getFormat() {
    return format;
  }

  /**
   * Set the format of the raw key data.
   */
  public void setFormat(String format) {
    this.format = format;
  }

  /**
   * Return the raw key data of the key.
   */
  public byte[] getRawKey() {
    return rawKey;
  }

  /**
   * Set the raw key data of the key.
   */
  public void setRawKey(byte[] rawKey) {
    this.rawKey = rawKey;
  }

  /**
   * Check whether the key is valid.
   * 
   * @return <code>true</code> if valid, <code>false</code> if not valid.
   */
  public boolean isValid() {
    if(keyType == null ||
        rawKey == null)
      return false;

    return true;
  } 

  /**
   * Derives a 256bit AES key from a password.
   * @param password The password to derive key from
   * @return The derived key
   * @throws CryptoException if error happens
   */
  public static Key derive(String password) throws CryptoException {
    return derive(password, AES, 256);
  }

  /**
   * Derives a key from a password with specified algorithm and length
   * @param password The password to derive key from
   * @param cryptographicAlgorithm The algorithm for the key
   * @param cryptographicLength The length of the key
   * @return The derived key
   * @throws CryptoException if error happens
   */
  public static Key derive(String password, String cryptographicAlgorithm, int cryptographicLength) throws CryptoException {
    if(!AES.equals(cryptographicAlgorithm))
      throw new CryptoException("Derive key is not supported for cryptographic algorithm " + cryptographicAlgorithm);

    byte[] rawKey = deriveKey(password, cryptographicLength);
    return new Key(KeyType.SYMMETRIC_KEY, cryptographicAlgorithm, cryptographicLength, rawKey);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (!(obj instanceof Key))
      return false;

    final Key other = (Key)obj;

    if(keyType != other.keyType)
      return false;

    if(rawKey == null) {
      if(other.rawKey != null)
        return false;
    } else {
      if(!Arrays.equals(rawKey, other.rawKey))
        return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }

  @Override
  public void write(DataOutput out) throws IOException {
    if(!isValid())
      throw new IOException("Unable to write invalid Key.");

    out.writeInt(keyType.ordinal());

    if(cryptographicAlgorithm != null) {
      out.writeBoolean(true);
      Text.writeString(out, cryptographicAlgorithm);
    } else {
      out.writeBoolean(false);
    }

    out.writeInt(cryptographicLength);

    if(format != null) {
      out.writeBoolean(true);
      Text.writeString(out, format);
    } else {
      out.writeBoolean(false);
    }

    WritableUtils.writeVInt(out, rawKey.length);
    out.write(rawKey);

  }

  @Override
  public void readFields(DataInput in) throws IOException {
    keyType = KeyType.values()[in.readInt()];

    boolean hascryptographicAlgorithm = in.readBoolean();
    if(hascryptographicAlgorithm)
      cryptographicAlgorithm = Text.readString(in);
    else
      cryptographicAlgorithm = null;

    cryptographicLength = in.readInt();

    boolean hasFormat = in.readBoolean();
    if(hasFormat)
      format = Text.readString(in);
    else
      format = null;

    int len = WritableUtils.readVInt(in);
    byte[] value = new byte[len];
    in.readFully(value);
    rawKey = value;
  }

  /**
   * Helper method to derive a 256 bit or 128 bit key from a password using SHA.
   */
  public static byte[] deriveKey(String password, int cryptographicLength) throws CryptoException {
    try {
      if(cryptographicLength == 256)
        return sha256(password.getBytes("UTF-8"));
      else
        return sha1(password.getBytes("UTF-8"));
    } catch (UnsupportedEncodingException ex) {
      throw new CryptoException(ex);
    }
  }

  /**
   * Helper method for generate 128bit SHA digest from a input.
   */
  public static byte[] sha1(byte[] input) throws CryptoException {
    try {
      MessageDigest sha;
      sha = MessageDigest.getInstance("SHA-1");
      sha.update(input);
      byte[] result = sha.digest();
      return Arrays.copyOf(result, 16);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException("Cannot generate native password from input key", e);
    } 
  }

  /**
   * Helper method for generate 256bit SHA digest from a input.
   */
  public static byte[] sha256(byte[] input) throws CryptoException {
    try {
      final byte[] result = new byte[32];
      MessageDigest sha256;
      sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(input);
      sha256.digest(result, 0, result.length);
      return result;
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoException("Cannot generate native password from input key", e);
    } catch (DigestException e) {
      throw new CryptoException("Cannot generate native password from input key", e);
    }
  }
}
