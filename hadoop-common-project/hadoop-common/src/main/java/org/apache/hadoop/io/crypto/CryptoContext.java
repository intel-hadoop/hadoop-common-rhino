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

import org.apache.hadoop.io.MD5Hash;

/**
 * This class representing the context of a {@link CryptoCodec} to do
 * an encryption or decryption. For example, the {@link Key} to encrypt the data.
 * The <code>CryptoContext</code> can be used in two ways.
 * 1. A <code>Key</code> is provided in the CryptoContext and the <code>Key</code> is used directly to
 * do the encryption or decryption.
 * 2. A {@link KeyProfile} and {@link KeyProfileResolver} can be provided and the <code>Key</code> is got by
 * calling <code>KeyProfileResolver</code> to resolve a given <code>KeyProfile</code> to a <code>Key</code>.
 * <code>KeyProfile</code> and <code>KeyProfileResolver</code> provides the flexibility for implementations
 * to store some key profile data with the encrypted data which can then be used when decrypting,
 * The stored key profile data will be used to resolve to the <code>Key</code> through the
 * specified <code>KeyProfileResolver</code>.
 */

public class CryptoContext {
  private Key key;
  private KeyProfile keyProfile;
  private KeyProfileResolver keyProfileResolver;

  /** A new crypto context. */
  public CryptoContext() {
  }

  /** A new crypto context specifying the {@link Key}, or 
   * {@link KeyProfile} and {@link KeyProfileResolver}. 
   * 
   * @param key The key for the crypto context
   * @param keyProfile The key profile data associate with the key if has
   * @param keyProfileResolver The key profile resolver for resovling to a key if has
   */
  public CryptoContext(Key key, KeyProfile keyProfile,
      KeyProfileResolver keyProfileResolver) {
    super();
    this.key = key;
    this.keyProfile = keyProfile;
    this.keyProfileResolver = keyProfileResolver;
  }

  /** Return the key of the crypto context. */
  public Key getKey() {
    return key;
  }

  /** Set a key to crypto context. */
  public void setKey(Key key) {
    this.key = key;
  }

  /** Return the key profile of the crypto context. */
  public KeyProfile getKeyProfile() {
    return keyProfile;
  }

  /** Set the key profile to the crypto context. */
  public void setKeyProfile(KeyProfile keyProfile) {
    this.keyProfile = keyProfile;
  }

  /** Return the key profile resolver of the crypto context. */
  public KeyProfileResolver getKeyProfileResolver() {
    return keyProfileResolver;
  }

  /** Set the key profile file resolver to the crypto context. */
  public void setKeyProfileResolver(KeyProfileResolver keyProfileResolver) {
    this.keyProfileResolver = keyProfileResolver;
  }

  /** Make a shallow copy from a existing crypto context. */
  public static CryptoContext makeCopy(CryptoContext original) {
    if(original == null)
      return null;

    return new CryptoContext(original.key, original.keyProfile, original.keyProfileResolver);
  }

  @Override
  public String toString() {
    StringBuffer sb = new StringBuffer();

    if(key != null) {
      MD5Hash digest = MD5Hash.digest(key.getRawKey());
      sb.append("Key MD5: ");
      sb.append(digest);
    } else {
      sb.append("Key MD5: none");
    }

    sb.append(", Key Profile:");
    sb.append(keyProfile);

    sb.append(", Key Profile Resolver: ");
    if(keyProfileResolver != null) {
      sb.append("Yes");
    } else {
      sb.append("No");
    }

    return sb.toString();
  }

}
