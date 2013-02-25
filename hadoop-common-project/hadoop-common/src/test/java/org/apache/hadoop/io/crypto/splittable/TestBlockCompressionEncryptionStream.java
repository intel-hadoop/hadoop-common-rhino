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

package org.apache.hadoop.io.crypto.splittable;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import junit.framework.TestCase;

import org.apache.hadoop.io.crypto.splittable.BlockDecryptionStream;
import org.apache.hadoop.io.crypto.splittable.BlockEncryptionStream;
import org.junit.Test;

public class TestBlockCompressionEncryptionStream extends TestCase {

  @Test(timeout=30000)
  public void testBlockCompressionEncryptionStream() throws IOException {

    FakeCompressor compressor = new FakeCompressor(512);
    FakeEncryptor encryptor = new FakeEncryptor("password", 2048);

    FakeDecompressor decompressor = new FakeDecompressor(512);
    FakeDecryptor decryptor = new FakeDecryptor("password", 2048);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    BlockEncryptionStream compressionOut = new FakeBlockEncryptionStream(out,
        new FakeEncryptorWithCompressor(encryptor, compressor, 2048, 16, 512,
            20), 2048);

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
    BlockDecryptionStream compressionIn = new FakeBlockDecryptionStream(in,
        new FakeDecryptorWithDecompressor(decryptor, decompressor, 2048), 2048);

    DataInputStream dataIn = new DataInputStream(compressionIn);
    long i = 0L;
    for (i = 0L; i < size; i++) {
      long data = dataIn.readLong();
      // System.out.print(data);
      assertEquals(i, data);
    }

    System.out.println("finished!");
  }
}
