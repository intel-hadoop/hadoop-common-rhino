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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import junit.framework.TestCase;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.junit.Test;

public class TestAESCodec extends TestCase {

  @Test(timeout=30000)
  public void testEncrypt() throws IOException {
    if(!AESCodec.isNativeCodeLoaded()){
      return;
    }
    AESCodec codec = new AESCodec();
    Configuration conf = new Configuration();
    codec.setConf(conf);

    CryptoContext cryptoContext = new CryptoContext();

    Key key = null;
    try {
      key = Key.derive("123456");
    } catch (CryptoException e) {
      e.printStackTrace();
    }
    cryptoContext.setKey(key);
    codec.setCryptoContext(cryptoContext);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    CompressionOutputStream compressionOut = codec.createOutputStream(out);
    DataOutputStream dataOut = new DataOutputStream(compressionOut);
    // dataOut.writ

    long size = 0x80000;
    for (long i = 0L; i < size; i++) {
      dataOut.writeLong(i);
      dataOut.flush();
    }
    dataOut.flush();
    compressionOut.finish();

    ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
    CompressionInputStream compressionIn = codec.createInputStream(in);
    DataInputStream dataIn = new DataInputStream(compressionIn);
    long i = 0L;
    for (i = 0L; i < size; i++) {
      long data = dataIn.readLong();
      assertEquals(i, data);
    }
  }

  @Test(timeout=30000)
  public void testCompressEncrypt() throws IOException {
    if(!AESCodec.isNativeCodeLoaded()){
      return;
    }
    AESCodec codec = new AESCodec();
    Configuration conf = new Configuration();
    conf.set(AESCodec.CRYPTO_COMPRESSOR,
        "org.apache.hadoop.io.compress.SnappyCodec");
    codec.setConf(conf);

    CryptoContext cryptoContext = new CryptoContext();

    Key key = null;
    try {
      key = Key.derive("123456");
    } catch (CryptoException e) {
      e.printStackTrace();
    }
    cryptoContext.setKey(key);
    codec.setCryptoContext(cryptoContext);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    CompressionOutputStream compressionOut = codec.createOutputStream(out);
    DataOutputStream dataOut = new DataOutputStream(compressionOut);
    // dataOut.writ

    long size = 0x80000;
    for (long i = 0L; i < size; i++) {
      dataOut.writeLong(i);
      dataOut.flush();
    }
    dataOut.flush();
    compressionOut.finish();

    ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
    CompressionInputStream compressionIn = codec.createInputStream(in);
    DataInputStream dataIn = new DataInputStream(compressionIn);
    long i = 0L;
    for (i = 0L; i < size; i++) {
      long data = dataIn.readLong();
      assertEquals(i, data);
    }
  }

  public static void main(String[] args) throws Exception {
    /*
     * Usage: Encrypt: {this program} -e inputFile outputFile Decrypt: {this
     * program} -d inputFile outputFile
     */
    System.out.print("Usage: \n"
        + "Encrypt: {this binary} -e inputFile outputFile -compress \n"
        + "Decrypt: {this binary} -d inputFile outputFile -compress \n");

    Configuration conf = new Configuration();
    boolean encrypt = "-e".equals(args[0]);
    String inputFile = args[1];
    String outputFile = args[2];

    int totalRead = 0;
    AESCodec codec = new AESCodec();

    CryptoContext cryptoContext = new CryptoContext();

    Key key = null;
    try {
      key = Key.derive("123456");
    } catch (CryptoException e) {
      e.printStackTrace();
    }
    cryptoContext.setKey(key);
    codec.setCryptoContext(cryptoContext);

    if (args.length > 3 && args[3].equals("-compress")) {
      conf.set(AESCodec.CRYPTO_COMPRESSOR,
          "org.apache.hadoop.io.compress.SnappyCodec");
    }

    ((AESCodec) codec).setConf(conf);

    totalRead = 0;
    long start = System.currentTimeMillis();
    try {
      final FileSystem fs = FileSystem.getLocal(new Configuration());
      final Path in = new Path(inputFile);
      final Path out = new Path(outputFile);

      byte[] buffer = new byte[1024 * 1024]; // 64k

      if (!encrypt) {
        InputStream inStream = codec.createInputStream(fs.open(in));
        int read = 0;
        OutputStream outStream = fs.create(out, true);
        while (0 < (read = inStream.read(buffer, 0, 64 * 1024))) {
          totalRead += read;
          outStream.write(buffer, 0, read);
        }
        outStream.flush();
        outStream.close();
      } else {
        OutputStream outStream = codec.createOutputStream(fs.create(out, true));
        int read = 0;
        InputStream inStream = fs.open(in);

        while (0 < (read = inStream.read(buffer, 0, 64 * 1024))) {
          totalRead += read;
          // System.out.print("Total read " + totalRead);
          outStream.write(buffer, 0, read);
        }
        outStream.flush();
        outStream.close();
      }
      fs.close();

    } catch (Throwable e) {
      e.printStackTrace();
    } finally {
      System.out.println("Total read: " + totalRead);
      System.out.println("Use time: " + (System.currentTimeMillis() - start)
          / 1000 + " s");
    }
  }

  public static byte[] toBytes(int val) {
    byte[] b = new byte[4];
    for (int i = 3; i > 0; i--) {
      b[i] = (byte) val;
      val >>>= 8;
    }
    b[0] = (byte) val;
    return b;
  }

  public static int toInt(byte[] decode) {
    int n = 0;
    for (int i = 0; i < (4); i++) {
      n <<= 8;
      n ^= decode[i] & 0xFF;
    }
    return n;
  }
}
