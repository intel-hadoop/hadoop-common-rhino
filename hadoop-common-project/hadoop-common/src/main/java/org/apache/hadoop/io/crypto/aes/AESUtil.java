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

package org.apache.hadoop.io.crypto.aes;

import java.io.UnsupportedEncodingException;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import org.apache.hadoop.io.crypto.CryptoException;

public class AESUtil {
  /**
   * Generate 256bit key for AES-256 or 128bit key for AES-128 from a password
   * 
   * @param password
   * @param cryptographicLength
   * @return the key byte array which is the length according to cryptographicLength
   * @throws CryptoException
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

  // length in bits
  public static byte[] randomBytes(int length) {
    Random rand = new Random();
    byte[] result = new byte[length / 8];
    rand.nextBytes(result);
    return result;
  }

  public static byte[] randomBytes(byte[] key) {
    Random rand = new Random();
    rand.nextBytes(key);
    return key;
  }
}
