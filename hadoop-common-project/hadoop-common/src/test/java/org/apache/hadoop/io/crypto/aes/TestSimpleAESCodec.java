/*
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

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;

import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.SequenceFile;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.crypto.CryptoCodec;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.PositionedReadableByteArrayInputStream;

import org.junit.Test;

public class TestSimpleAESCodec {

  @Test(timeout=30000)
  public void testSimpleAESCodec() throws Exception {
    if (!AESCodec.isNativeCodeLoaded()) {
      return;
    }

    Configuration conf = new Configuration();
    SimpleAESCodec codec = new SimpleAESCodec();
    ((Configurable)codec).setConf(conf);
    CryptoContext cryptoContext = new CryptoContext();
    cryptoContext.setKey(Key.derive("123456"));
    codec.setCryptoContext(cryptoContext);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    CompressionOutputStream compressionOut = codec.createOutputStream(out);
    DataOutputStream dataOut = new DataOutputStream(compressionOut);
    long size = 0x80000L;
    for (long i = 0L; i < size; i++) {
      dataOut.writeLong(i);
    }
    dataOut.flush();
    compressionOut.flush();
    compressionOut.finish();

    ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
    CompressionInputStream compressionIn = codec.createInputStream(in);
    DataInputStream dataIn = new DataInputStream(compressionIn);
    for (long i = 0L; i < size; i++) {
      long data = dataIn.readLong();
      assertEquals(i, data);
    }
  }

  @Test(timeout=30000)
  public void testSimpleAESCodecSmallBlock() throws Exception {
    if (!AESCodec.isNativeCodeLoaded()) {
      return;
    }

    int size = 100;

    Configuration conf = new Configuration();
    SimpleAESCodec codec = new SimpleAESCodec();
    conf.setInt(SimpleAESCodec.BLOCK_SIZE_KEY, 48);
    ((Configurable)codec).setConf(conf);
    CryptoContext cryptoContext = new CryptoContext();
    cryptoContext.setKey(Key.derive("123456"));
    codec.setCryptoContext(cryptoContext);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    CompressionOutputStream compressionOut = codec.createOutputStream(out);
    for (int i = 0; i < size; i++) {
      compressionOut.write(i);
    }
    compressionOut.flush();
    compressionOut.finish();

    ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
    CompressionInputStream compressionIn = codec.createInputStream(in);
    for (int i = 0; i < size; i++) {
      int data = compressionIn.read();
      assertEquals(i, data);
    }
  }

  @Test(timeout=30000)
  @SuppressWarnings("deprecation")
  public void testSequenceFileSimpleAESCodecBlockCompression()
      throws Exception {
    if (!AESCodec.isNativeCodeLoaded()) {
      return;
    }

    Configuration conf = new Configuration();
    CryptoContext context = new CryptoContext();
    context.setKey(Key.derive("123456"));
    CryptoCodec codec = new SimpleAESCodec();
    ((Configurable)codec).setConf(conf);
    codec.setCryptoContext(context);

    long size = 1000L;

    // Write a sequence file using the AES codec
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    FSDataOutputStream out = new FSDataOutputStream(baos, null);
    SequenceFile.Writer writer = SequenceFile.createWriter(conf, out,
      LongWritable.class, LongWritable.class,
      SequenceFile.CompressionType.BLOCK, codec);
    try {
      for (long i = 0; i < size; i++) {
        writer.append(new LongWritable(i), new LongWritable(i));
      }
    } finally {
      writer.close();
    }

    // Read it back
    byte[] bytes = baos.toByteArray();
    FSDataInputStream in =
      new FSDataInputStream(new PositionedReadableByteArrayInputStream(bytes));
    SequenceFile.Reader reader = new SequenceFile.Reader(in, 4096, 0,
      bytes.length, conf, context);
    assertTrue(reader.isCompressed());
    assertEquals(SequenceFile.CompressionType.BLOCK, reader.getCompressionType());
    assertEquals(SimpleAESCodec.class, reader.getCompressionCodec().getClass());
    assertEquals(LongWritable.class, reader.getKeyClass());
    assertEquals(LongWritable.class, reader.getValueClass());
    try {
      LongWritable key = new LongWritable();
      LongWritable value = new LongWritable();
      for (long i = 0; i < size; i++) {
        reader.next(key, value);
        assertEquals(key.get(), i);
        assertEquals(value.get(), i);
      }
    } finally {
      reader.close();
    }
  }
}
