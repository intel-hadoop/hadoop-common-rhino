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
import java.io.UnsupportedEncodingException;

import junit.framework.TestCase;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.KeyProfile;
import org.apache.hadoop.io.crypto.KeyProfileResolver;
import org.junit.Test;

public class TestAESCodecKey extends TestCase {
  @Test(timeout=30000)
  public void testEncrypt() throws IOException {
    if(!AESCodec.isNativeCodeLoaded()){
      return;
    }
    AESCodec codece = new AESCodec();
    Configuration conf = new Configuration();
    codece.setConf(conf);

    CryptoContext cryptoContext = new CryptoContext();

    Key key = null;
    try {
      key = Key.derive("123456");
    } catch (CryptoException e) {
      e.printStackTrace();
    }
    cryptoContext.setKey(key);
    codece.setCryptoContext(cryptoContext);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    CompressionOutputStream compressionOut = codece.createOutputStream(out);
    DataOutputStream dataOut = new DataOutputStream(compressionOut);

    long size = 0x80000;
    for (long i = 0L; i < size; i++) {
      dataOut.writeLong(i);
      dataOut.flush();
    }
    dataOut.flush();
    compressionOut.finish();

    AESCodec codecd = new AESCodec();
    codecd.setCryptoContext(cryptoContext);

    ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
    CompressionInputStream compressionIn = codecd.createInputStream(in);
    DataInputStream dataIn = new DataInputStream(compressionIn);
    long i = 0L;
    for (i = 0L; i < size; i++) {
      long data = dataIn.readLong();
      assertEquals(i, data);
    }
  }

  private static class MyKeyProfileResolver implements KeyProfileResolver {

    @Override
    public Key resolve(KeyProfile keyProfile) throws CryptoException {
      byte[] data = keyProfile.getData();
      try {
        String password = new String(data, "UTF-8");
        return Key.derive(password);
      } catch (UnsupportedEncodingException e) {
        throw new CryptoException(e);
      }
    }

  }

  @Test(timeout=30000)
  public void testKeyProfile() throws IOException {
    if(!AESCodec.isNativeCodeLoaded()){
      return;
    }
    AESCodec codece = new AESCodec();
    Configuration conf = new Configuration();
    codece.setConf(conf);

    CryptoContext cryptoContext = new CryptoContext();
    cryptoContext.setKeyProfile(new KeyProfile("KEY00".getBytes("UTF-8")));
    cryptoContext.setKeyProfileResolver(new MyKeyProfileResolver());
    codece.setCryptoContext(cryptoContext);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    CompressionOutputStream compressionOut = codece.createOutputStream(out);
    DataOutputStream dataOut = new DataOutputStream(compressionOut);

    long size = 0x80000;
    for (long i = 0L; i < size; i++) {
      dataOut.writeLong(i);
      dataOut.flush();
    }
    dataOut.flush();
    compressionOut.finish();

    AESCodec codecd = new AESCodec();

    codecd.setCryptoContext(cryptoContext);

    ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
    CompressionInputStream compressionIn = codecd.createInputStream(in);
    DataInputStream dataIn = new DataInputStream(compressionIn);
    long i = 0L;
    for (i = 0L; i < size; i++) {
      long data = dataIn.readLong();
      assertEquals(i, data);
    }
  }

}
