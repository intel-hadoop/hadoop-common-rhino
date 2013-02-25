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
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import junit.framework.TestCase;
import org.junit.Test;

public class TestNativeOpensslAESCipher extends TestCase {
  Charset UTF_8 = Charset.forName("UTF-8");

  private byte[] key;
  private byte[] iv;
  private byte[] iv2;

  @Override
  protected void setUp() {
    key = new byte[32];
    iv = new byte[16];
    iv2 = new byte[16];

    key = ZeroString(32).getBytes(UTF_8);
    iv = CharString('1', 16).getBytes(UTF_8);
    iv2 = CharString('2', 16).getBytes(UTF_8);

    try {
      System.out.print("key:" + toStringBinary(key) + "\n");
      System.out.print("iv: " + toStringBinary(iv) + "\n");
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
  }

  @Test(timeout=30000)
  public void testDirectBufferDoFinal() throws Exception {
    if(!NativeOpensslAESCipher.isNativeCodeLoaded()){
      return;
    }
    System.out.print("\n\nTest do final direct buffer\n=====\n\n");

    int directBufferSize = 1024;
    ByteBuffer uncompressedDirectBuf = ByteBuffer
        .allocateDirect(directBufferSize);
    ByteBuffer compressedDirectBuf = ByteBuffer
        .allocateDirect(directBufferSize);

    String rawData = CharString('c', 200);
    uncompressedDirectBuf.put(rawData.substring(0, 100).getBytes());
    int uncompressedDirectBufLen = uncompressedDirectBuf.position();
    NativeOpensslAESCipher encryptor = new NativeOpensslAESCipher();
    encryptor.init(NativeOpensslAESCipher.Mode.ENCRYPT, key, iv);

    NativeOpensslAESCipher decryptor = new NativeOpensslAESCipher();
    decryptor.init(NativeOpensslAESCipher.Mode.DECRYPT, key, iv);
    int compressedLength = encryptor.doFinal(uncompressedDirectBuf,
        uncompressedDirectBufLen, compressedDirectBuf);

    byte[] result = new byte[compressedLength];
    compressedDirectBuf.get(result, 0, compressedLength);

    System.out.print("\nencrypted: " + toStringBinary(result) + ", length: "
        + result.length + "\n");

    int uncompressedLength = decryptor.doFinal(compressedDirectBuf,
        compressedLength, uncompressedDirectBuf);

    result = new byte[uncompressedLength];
    uncompressedDirectBuf.get(result, 0, uncompressedLength);

    System.out.print("\ndecrypted: " + toStringBinary(result) + ", length: "
        + result.length + "\n");

    encryptor.reset(null, iv2);
    decryptor.reset(null, iv2);

    compressedLength = encryptor.doFinal(uncompressedDirectBuf,
        uncompressedLength, compressedDirectBuf);

    result = new byte[compressedLength];
    compressedDirectBuf.get(result, 0, compressedLength);

    System.out.print("\nencrypted: " + toStringBinary(result) + ", length: "
        + result.length + "\n");

    uncompressedLength = decryptor.doFinal(compressedDirectBuf,
        compressedLength, uncompressedDirectBuf);

    result = new byte[uncompressedLength];
    uncompressedDirectBuf.get(result, 0, uncompressedLength);

    System.out.print("\ndecrypted: " + toStringBinary(result) + ", length: "
        + result.length + "\n");

  }

  @Test(timeout=30000)
  public void testBlockSizePerformanceRelation() throws Exception {
    if(!NativeOpensslAESCipher.isNativeCodeLoaded()){
      return;
    }
    int directBufferSize = 1024 * 1024;
    ByteBuffer uncompressedDirectBuf = ByteBuffer
        .allocateDirect(directBufferSize);
    ByteBuffer compressedDirectBuf = ByteBuffer
        .allocateDirect(directBufferSize + 256);

    byte[] raw = ZeroString(1024).getBytes(UTF_8);
    for (int i = 0; i < 64; i++) {
      uncompressedDirectBuf.put(raw);
    }

    NativeOpensslAESCipher encryptor = new NativeOpensslAESCipher();
    encryptor.init(NativeOpensslAESCipher.Mode.ENCRYPT, key, iv);

    long startTime = System.currentTimeMillis();

    int blockSize = 1024 * 1024;
    long totalSize = 1024L * 1024 * 1024 * 4;
    System.out.print("total size: " + totalSize / 1024 / 1024 + " M");
    for (int i = 0; i < totalSize / blockSize; i++) {
      encryptor.doFinal(uncompressedDirectBuf, blockSize,
          compressedDirectBuf);
    }

    System.out.print("\n======OpenSSL AES256  cipher: " + "block size, "
        + blockSize + ", time, " + totalSize / blockSize
        + String.valueOf((System.currentTimeMillis() - startTime) + " ms\n"));

    startTime = System.currentTimeMillis();

    blockSize = 1024 * 64;
    for (int i = 0; i < totalSize / blockSize; i++) {
      encryptor.doFinal(uncompressedDirectBuf, blockSize,
          compressedDirectBuf);
    }

    System.out.print("\n======OpenSSL AES256  cipher: " + "block size, "
        + blockSize + ", " + ", time, " + totalSize / blockSize
        + String.valueOf((System.currentTimeMillis() - startTime) + " ms\n"));

    startTime = System.currentTimeMillis();

    blockSize = 1024 * 16;
    for (int i = 0; i < totalSize / blockSize; i++) {
      encryptor.doFinal(uncompressedDirectBuf, blockSize,
          compressedDirectBuf);
    }

    System.out.print("\n======OpenSSL AES256  cipher: " + "block size, "
        + blockSize + "," + ", time, " + totalSize / blockSize
        + String.valueOf((System.currentTimeMillis() - startTime) + " ms\n"));

  }

  public static void main(String[] args) throws Exception {

    TestNativeOpensslAESCipher test = new TestNativeOpensslAESCipher();
    test.setUp();
    test.testDirectBufferDoFinal();
    // test.testPerformance();
  }

  private static String ZeroString(int length) {
    if (length == 0) {
      return "";
    }
    String result = "";
    for (int i = 0; i < length; i++) {
      result += "0";
    }
    return result;
  }

  private static String CharString(char c, int length) {
    if (length == 0) {
      return "";
    }
    String result = "";
    for (int i = 0; i < length; i++) {
      result += c;
    }
    return result;
  }

  public static String toStringBinary(final byte[] b)
      throws UnsupportedEncodingException {
    if (b == null) {
      return "null";
    }
    return toStringBinary(b, 0, b.length);
  }

  /**
   * Write a printable representation of a byte array. Non-printable characters
   * are hex escaped in the format \\x%02X, eg: \x00 \x05 etc
   * 
   * @param b
   *          array to write out
   * @param off
   *          offset to start at
   * @param len
   *          length to write
   * @return string output
   * @throws UnsupportedEncodingException
   */
  public static String toStringBinary(final byte[] b, int off, int len)
      throws UnsupportedEncodingException {
    StringBuilder result = new StringBuilder();
    String first = new String(b, off, len, "ISO-8859-1");
    for (int i = 0; i < first.length(); ++i) {
      int ch = first.charAt(i) & 0xFF;
      if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')
          || (ch >= 'a' && ch <= 'z')
          || " `~!@#$%^&*()-_=+[]{}\\|;:'\",.<>/?".indexOf(ch) >= 0) {
        result.append(first.charAt(i));
      } else {
        result.append(String.format("\\x%02X", ch));
      }
    }
    return result.toString();
  }
}
