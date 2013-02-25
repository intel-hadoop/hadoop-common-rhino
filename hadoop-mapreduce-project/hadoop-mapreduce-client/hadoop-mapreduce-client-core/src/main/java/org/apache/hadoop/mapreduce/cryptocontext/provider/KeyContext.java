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
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.Key.KeyType;
import org.apache.hadoop.util.StringUtils;

/**
 * A <code>KeyContext</code> is an abstract data structure that represents something
 * that can be converted to a key through some mechanism such as key storage lookup.
 */

public class KeyContext implements Writable {

  /**
   * The type of the key context which can be a raw key, reference to a key or opaque thing that
   * interpreted by the implementation. 
   */
  public enum KeyContextType {
    RAWKEY,
    REFERENCE,
    OPAQUE;
  }

  private KeyContextType type = KeyContextType.RAWKEY;
  private KeyType keyType = KeyType.SYMMETRIC_KEY;
  private String cryptographicAlgorithm;
  private int cryptographicLength = 256;
  private byte[] data;

  /**
   * A new key context object.
   */
  public KeyContext() {
  }

  /**
   * A new key context object by specifying the attributes.
   */
  public KeyContext(KeyContextType type, KeyType keyType,
      String cryptographicAlgorithm, int cryptographicLength, byte[] data) {
    this.type = type;
    this.keyType = keyType;
    this.cryptographicAlgorithm = cryptographicAlgorithm;
    this.cryptographicLength = cryptographicLength;
    this.data = data;
  }

  /**
   * Return the type of the key context.
   */
  public KeyContextType getType() {
    return type;
  }

  /**
   * Set the type of the key context.
   */
  public void setType(KeyContextType type) {
    this.type = type;
  }

  /**
   * Return the key type of the key that the key context associates to.
   */
  public KeyType getKeyType() {
    return keyType;
  }

  /**
   * Set the key type of the key that the key context associates to.
   */
  public void setKeyType(KeyType keyType) {
    this.keyType = keyType;
  }

  /**
   * Get the cryptographic algorithm of the key that the key context associates to.
   */
  public String getCryptographicAlgorithm() {
    return cryptographicAlgorithm;
  }

  /**
   * Set the cryptographic algorithm of the key that the key context associates to.
   */
  public void setCryptographicAlgorithm(
      String cryptographicAlgorithm) {
    this.cryptographicAlgorithm = cryptographicAlgorithm;
  }

  /**
   * Get the cryptographic length of the key that the key context associates to.
   */
  public int getCryptographicLength(){
    return cryptographicLength;
  }

  /**
   * Get the cryptographic length of the key that the key context associates to.
   */
  public void setCryptographicLength(int cryptographicLength) {
    this.cryptographicLength = cryptographicLength;
  }

  /**
   * Get the data part of the key context.
   */
  public byte[] getData() {
    return data;
  }

  /**
   * Set the data part of the key context.
   */
  public void setData(byte[] data) {
    this.data = data;
  }

  /**
   * Check whether the key context is valid or not
   */
  public boolean isValid() {
    if( type == null ||
        data == null )
      return false;

    return true;
  }

  /**
   * Return the string presentation of the key context.
   */
  public String getEncoded() {
    return toString();
  }

  /**
   * Deserialize the key context from a byte array.
   */
  public static KeyContext from(byte[] input) throws IOException {
    if(input == null || 
        input.length <= 0)
      return null;

    ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
    DataInputStream in = new DataInputStream(inputStream);

    KeyContext keyContext = new KeyContext();
    keyContext.readFields(in);
    return keyContext;
  }

  /**
   * Helper method to create a new key context for a key.
   */
  public static KeyContext fromKey(Key key) {
    return new KeyContext(KeyContextType.RAWKEY, key.getKeyType(),
        key.getCryptographicAlgorithm(), key.getCryptographicLength(), key.getRawKey());
  }

  /**
   * Convert a raw key context to a key.
   */
  public Key toKey() throws CryptoException {
    if( type != KeyContextType.RAWKEY)
      throw new CryptoException("Invalid key context type. RAWKEY context type is needed.");

    return new Key(getKeyType(), getCryptographicAlgorithm(), getCryptographicLength(), getData());
  }

  /**
   * Convert a reference key context to a reference string.
   */
  public String toReference() throws CryptoException {
    if( type != KeyContextType.REFERENCE)
      throw new CryptoException("Invalid key context type. REFERENCE context type is needed.");

    try {
      return new String(data, "UTF-8");
    } catch(UnsupportedEncodingException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Helper method to create a KeyContext for deriving a AES key from a password. 
   */
  public static KeyContext derive(String password) throws CryptoException {
    return fromKey(Key.derive(password));
  }

  /**
   * Helper method to create a KeyContext for deriving a AES key from a password. 
   */
  public static KeyContext derive(String password, String cryptographicAlgorithm, int cryptographicLength) throws CryptoException {
    return fromKey(Key.derive(password, cryptographicAlgorithm, cryptographicLength));
  }

  /**
   * Helper method to create a KeyContext for referring a given reference id. 
   */
  public static KeyContext refer(String key) throws CryptoException {
    return refer(key, KeyType.SYMMETRIC_KEY, null, 256);
  }

  /**
   * Helper method to create a KeyContext for referring a given reference id. 
   */
  public static KeyContext refer(String key, KeyType keyType, String cryptographicAlgorithm, int cryptographicLength) throws CryptoException {
    try {
      return new KeyContext(KeyContextType.REFERENCE, keyType,
          cryptographicAlgorithm, cryptographicLength, key.getBytes("UTF-8"));
    } catch(UnsupportedEncodingException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Helper method to create a opaque KeyContext by specifying the raw data. 
   */
  public static KeyContext opaque(byte[] key) throws CryptoException {
    return opaque(key, KeyType.SYMMETRIC_KEY, null, 256);
  }

  /**
   * Helper method to create a opaque KeyContext by specifying the raw data. 
   */
  public static KeyContext opaque(byte[] key, KeyType keyType, String cryptographicAlgorithm, int cryptographicLength) throws CryptoException {
    return new KeyContext(KeyContextType.OPAQUE, keyType,
        cryptographicAlgorithm, cryptographicLength, key);
  }

  /**
   * Serialize the key context to byte array.
   */
  public byte[] toBytes() throws CryptoException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(outputStream);

    try {
      write(out);
    } catch(IOException e) {
      throw new CryptoException(e);
    }

    return outputStream.toByteArray();
  }

  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer();

    sb.append("Type: ");
    sb.append(type);
    
    sb.append("KeyType: ");
    sb.append(keyType.name());

    sb.append(", Cryptographic Algorithm: ");
    sb.append(cryptographicAlgorithm);

    sb.append(", Cryptographic Length: ");
    sb.append(cryptographicLength);

    sb.append(", Context Data: ");
    if(data != null)
      sb.append(StringUtils.byteToHexString(data));

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (!(obj instanceof KeyContext))
      return false;

    final KeyContext other = (KeyContext)obj;

    if(type != other.type)
      return false;
    
    if(!keyType.equals(other.getKeyType()))
      return false;

    if(cryptographicAlgorithm == null) {
      if(other.cryptographicAlgorithm != null)
        return false;
    } else {
      if(!cryptographicAlgorithm.equals(other.cryptographicAlgorithm))
        return false;
    }

    if(cryptographicLength != other.cryptographicLength)
      return false;

    if(data == null) {
      if(other.data != null)
        return false;
    } else {
      if(!Arrays.equals(data, other.data))
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
      throw new IOException("Unable to write invalid KeyContext.");

    out.writeInt(type.ordinal());
    out.writeInt(keyType.ordinal());
    
    if(cryptographicAlgorithm != null) {
      out.writeBoolean(true);
      Text.writeString(out, cryptographicAlgorithm);
    } else {
      out.writeBoolean(false);
    }

    out.writeInt(cryptographicLength);

    WritableUtils.writeVInt(out, data.length);
    out.write(data);
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    type = KeyContextType.values()[in.readInt()];
    keyType = KeyType.values()[in.readInt()];
    
    boolean hascryptographicAlgorithm = in.readBoolean();
    if(hascryptographicAlgorithm)
      cryptographicAlgorithm = Text.readString(in);
    else
      cryptographicAlgorithm = null;

    cryptographicLength = in.readInt();

    int len = WritableUtils.readVInt(in);
    byte[] value = new byte[len];
    in.readFully(value);

    data = value;
  }
}
