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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.crypto.CryptoCodec;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;

/**
 * Implements AES encryption and decryption as a simple compression codec.
 * Does not support the optional compression or splittable format of the
 * {@link AESCodec}. Does not do cipher block chaining. OpenSSL is used as
 * the native AES library. To get a good performance, it's best to use
 * openssl 1.0.1c and run on AES-NI enabled servers.
 */
public class SimpleAESCodec implements CryptoCodec, Configurable {

  public static final String BLOCK_SIZE_KEY = "hadoop.io.crypto.simpleaes.block.size";
  public static final int DEFAULT_BLOCK_SIZE = 256 * 1024;

  private static final Log LOG = LogFactory.getLog(SimpleAESCodec.class);

  private int blockSize = DEFAULT_BLOCK_SIZE;
  private Configuration conf;
  private CryptoContext cryptoContext;

  public static boolean isNativeCodeLoaded() {
    return AESEncryptor.isNativeCodeLoaded() && 
        AESDecryptor.isNativeCodeLoaded();
  }

  @Override
  public Class<? extends Compressor> getCompressorType() {
    AESCodec.checkNativeCodeLoaded();
    return AESEncryptor.class;
  }

  @Override
  public Compressor createCompressor() {
    AESCodec.checkNativeCodeLoaded();
    return new AESEncryptor(CryptoContext.makeCopy(cryptoContext), blockSize);
  }

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out)
      throws IOException {
    AESCodec.checkNativeCodeLoaded();
    return createOutputStream(out, createCompressor());
  }

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out,
      Compressor compressor) throws IOException {
    AESCodec.checkNativeCodeLoaded();
    AESEncryptor encryptor = (AESEncryptor)compressor; 
    CryptoContext context = encryptor.getCryptoContext();
    if (context == null) {
      encryptor.setCryptoContext(cryptoContext);
    }
    return new SimpleAESCompressionOutputStream(out, encryptor, blockSize);
  }

  @Override
  public Class<? extends Decompressor> getDecompressorType() {
    AESCodec.checkNativeCodeLoaded();
    return AESDecryptor.class;
  }

  @Override
  public Decompressor createDecompressor() {
    AESCodec.checkNativeCodeLoaded();
    try {
      return new AESDecryptor(CryptoContext.makeCopy(cryptoContext), blockSize);
    } catch (CryptoException e) {
      LOG.error(e);
      return null;
    }
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in)
      throws IOException {
    AESCodec.checkNativeCodeLoaded();
    return createInputStream(in, createDecompressor());
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in,
      Decompressor decompressor) throws IOException {
    AESCodec.checkNativeCodeLoaded();
    AESDecryptor decryptor = (AESDecryptor)decompressor; 
    CryptoContext context = decryptor.getCryptoContext();
    if (context == null) {
      decryptor.setCryptoContext(cryptoContext);
    }
    return new SimpleAESCompressionInputStream(in, decryptor, blockSize);
  }

  @Override
  public String getDefaultExtension() {
    return ".aes";
  }

  @Override
  public Configuration getConf() {
    return conf;
  }

  @Override
  public void setConf(Configuration conf) {
    this.conf = conf;
    this.blockSize = conf.getInt(BLOCK_SIZE_KEY, DEFAULT_BLOCK_SIZE);
  }

  @Override
  public CryptoContext getCryptoContext() {
    return cryptoContext;
  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {
    this.cryptoContext = cryptoContext;
  }

  /*
   * Internal block header format:
   * +---------------------+
   * | 4 byte block length |
   * +---------------------+
   * | 16 byte IV          |
   * +---------------------+
   * | encrypted data ...  |
   * +---------------------+
   */

  private static class SimpleAESCompressionInputStream
      extends CompressionInputStream {

    private AESDecryptor decryptor;
    private ByteBuffer buffer;
    byte[] iv = new byte[AESConstants.IV_LENGTH];

    protected SimpleAESCompressionInputStream(InputStream in,
        AESDecryptor decryptor, int blockSize) throws IOException {
      super(in);
      this.decryptor = decryptor;
      this.buffer = ByteBuffer.allocate(blockSize);
      this.buffer.limit(0);
    }

    @Override
    public void resetState() throws IOException {
      buffer.clear();
      buffer.limit(0);
      decryptor.reset();
    }

    private int readRawInt(InputStream in) throws IOException {
      int b1 = in.read();
      int b2 = in.read();
      int b3 = in.read();
      int b4 = in.read();
      if ((b1 | b2 | b3 | b4) < 0){
        return -1;
      }
      return ((b1 << 24) + (b2 << 16) + (b3 << 8) + (b4 << 0));
    }

    private int safeRead(InputStream in,  byte[] buf, int off, int len)
        throws IOException {
      int read = 0;
      while(read < len){
        int n = in.read(buf, off + read, len - read);
        if(read == 0 && n == -1){
          return -1;
        } else if(n == -1){
          break;
        } else {
          read += n;
        }
      }
      return read;
    }

    private int readNextBlock() throws IOException {
      // read header
      int blockLen = readRawInt(in);
      if(blockLen < 0){
        return -1;
      }
      if (blockLen > buffer.capacity()) {
        throw new IOException("Invalid block length " + blockLen);
      }
      if (safeRead(in, iv, 0, iv.length) != iv.length) {
        throw new IOException("Short IV");
      }

      // read data
      buffer.clear();
      buffer.limit(0);
      if (safeRead(in, buffer.array(), 0, blockLen) != blockLen) {
        throw new IOException("Short block");
      }
      decryptor.setIV(iv);
      decryptor.setInput(buffer.array(), 0, blockLen);

      int n = decryptor.decrypt(buffer.array(), 0, buffer.capacity());
      buffer.limit(n);

      return n;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (b == null) {
        throw new NullPointerException();
      } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length)) {
        throw new IndexOutOfBoundsException();
      } else if (len == 0) {
        return 0;
      }

      byte[] buf = buffer.array();
      int bufPos = buffer.position();
      int bufLimit = buffer.limit();
      int bufSize = bufLimit - bufPos;
      if (bufSize >= len) {
        System.arraycopy(buf, bufPos, b, off, len);
        if (bufSize == len) {
          buffer.clear();
          buffer.limit(0);
        } else {
          buffer.position(bufPos + len);
        }
        return len;
      } else if (bufSize > 0) {
        System.arraycopy(buf, bufPos, b, off, bufSize);
        buffer.clear();
        buffer.limit(0);
        return bufSize;
      }

      // read data from next block
      int read = readNextBlock();
      if (read < 0) {
        return -1;
      }

      if (read >= len) {
        buffer.get(b, off, len);
        if (read > len) { // cache the remaining data to buffer
          buffer.position(len);
        }
        return len;
      } else {
        buffer.get(b, off, read);
        buffer.clear();
        buffer.limit(0);
        return read;
      }
    }

    @Override
    public int read() throws IOException {
      byte[] b = new byte[1];
      return (read(b, 0, 1) == -1) ? -1 : (b[0] & 0xff);
    }
  }

  private static class SimpleAESCompressionOutputStream
      extends CompressionOutputStream {

    private AESEncryptor encryptor;
    private int blockSize;
    private byte[] iv = new byte[AESConstants.IV_LENGTH];
    private byte[] buffer;

    protected SimpleAESCompressionOutputStream(OutputStream out,
        AESEncryptor encryptor, int blockSize) {
      super(out);
      this.encryptor = encryptor;
      this.blockSize = blockSize;
      this.buffer = new byte[blockSize];
      AESUtil.randomBytes(iv);
      encryptor.setIV(iv);
    }

    private void writeRawInt(OutputStream out, int v) throws IOException {
      out.write((v >>> 24) & 0xFF);
      out.write((v >>> 16) & 0xFF);
      out.write((v >>> 8) & 0xFF);
      out.write((v >>> 0) & 0xFF);
    }

    private void incrementIV(byte[] iv){
      int length = iv.length;
      boolean carry = true;
      for (int i = 0; i < length; i++) {
        if (carry) {
          iv[i] = (byte) ((iv[i] + 1) & 0xFF);
          carry = 0 == iv[i];
        } else {
          break;
        }
      }
    }

    private int writeBlock() throws IOException {
      if (encryptor.getBytesRead() == 0) {
        return 0;
      }

      int blockLen = encryptor.encrypt(buffer, 0, buffer.length);

      // write header
      writeRawInt(out, blockLen);
      out.write(iv);

      // write data
      out.write(buffer, 0, blockLen);

      // update CTR mode cipher block chaining
      incrementIV(iv);
      encryptor.setIV(iv);

      return blockLen;
    }

    @Override
    public void flush() throws IOException {
      out.flush();
    }

    @Override
    public void finish() throws IOException {
      encryptor.finish();
      while (!encryptor.finished() && encryptor.getBytesRead() > 0) {
        writeBlock();
      }
      flush();
    }

    @Override
    public void resetState() throws IOException {
      encryptor.reset();
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      if (b == null) {
        throw new NullPointerException();
      } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length)) {
        throw new IndexOutOfBoundsException();
      } else if (len == 0) {
        return;
      }
      while (len > 0) {
        int n = len > blockSize ? blockSize : len;
        encryptor.setInput(b, off, n);
        while (!encryptor.needsInput()) {
          writeBlock();
        }
        off += n;
        len -= n;
      }
    }

    @Override
    public void write(int i) throws IOException {
      write(new byte[] { (byte) i }, 0, 1);
    }
  }
}
