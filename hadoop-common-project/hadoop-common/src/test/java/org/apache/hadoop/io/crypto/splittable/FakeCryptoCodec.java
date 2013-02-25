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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.compress.SplitCompressionInputStream;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.splittable.SplittableCryptoCodec;

public class FakeCryptoCodec implements SplittableCryptoCodec {

  public void FakeCryptoCode() {

  }

  @Override
  public SplitCompressionInputStream createInputStream(InputStream seekableIn,
      Decompressor decompressor, long start, long end, READ_MODE readMode)
      throws IOException {
    if (!(decompressor instanceof FakeDecryptorWithDecompressor)) {
      throw new RuntimeException("Incorrect decompressor type");
    }

    FakeDecryptorWithDecompressor decryptorWithDecompressor = (FakeDecryptorWithDecompressor) decompressor;

    return new FakeBlockDecryptionStream(seekableIn, decryptorWithDecompressor,
        start, end, readMode, 2048);
  }

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out)
      throws IOException {
    return createOutputStream(out, createCompressor());
  }

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out,
      Compressor compressor) throws IOException {
    if (!(compressor instanceof FakeEncryptorWithCompressor)) {
      throw new RuntimeException("Incorrect compressor type");
    }

    FakeEncryptorWithCompressor fakeEncryptorWithCompressor = (FakeEncryptorWithCompressor) compressor;

    return new FakeBlockEncryptionStream(out, fakeEncryptorWithCompressor, 2048);
  }

  @Override
  public Class<? extends Compressor> getCompressorType() {
    return FakeEncryptorWithCompressor.class;
  }

  @Override
  public Compressor createCompressor() {
    FakeCompressor compressor = new FakeCompressor(512);
    FakeEncryptor encryptor = new FakeEncryptor("password", 2048);

    return new FakeEncryptorWithCompressor(encryptor, compressor, 2048, 16,
        512, 20);
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in)
      throws IOException {
    return createInputStream(in, createDecompressor());
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in,
      Decompressor decompressor) throws IOException {
    if (!(decompressor instanceof FakeDecryptorWithDecompressor)) {
      throw new RuntimeException("Incorrect decompressor type");
    }

    FakeDecryptorWithDecompressor fakeDecryptorWithDecompressor = (FakeDecryptorWithDecompressor) decompressor;

    return new FakeBlockDecryptionStream(in, fakeDecryptorWithDecompressor,
        2048);
  }

  @Override
  public Class<? extends Decompressor> getDecompressorType() {
    return FakeDecryptorWithDecompressor.class;
  }

  @Override
  public Decompressor createDecompressor() {
    FakeDecompressor decompressor = new FakeDecompressor(512);
    FakeDecryptor decryptor = new FakeDecryptor("password", 2048);

    return new FakeDecryptorWithDecompressor(decryptor, decompressor, 2048);
  }

  @Override
  public String getDefaultExtension() {
    return null;
  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {

  }

  @Override
  public CryptoContext getCryptoContext() {
    return null;
  }

}
