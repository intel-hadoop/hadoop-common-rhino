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

import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.splittable.BlockDecryptor;
import org.apache.hadoop.util.NativeCodeLoader;

final public class AESDecryptor extends BlockDecryptor {
  private static final Log LOG = LogFactory.getLog(AESEncryptor.class.getName());

  private NativeOpensslAESCipher cipher = new NativeOpensslAESCipher();

  private int directBufferSize;
  private ByteBuffer compressedDirectBuf = null;
  private int compressedDirectBufLen;
  private ByteBuffer uncompressedDirectBuf = null;
  private byte[] userBuf = null;
  private int userBufOff = 0, userBufLen = 0;
  private boolean allInputProcessed;

  private CryptoContext cryptoContext;
  
  private Key key;
  
  private boolean initCalled = false;
  
  private static boolean nativeCryptoLoaded = false;
  
  static {
    if (NativeCodeLoader.isNativeCodeLoaded() &&
        NativeCodeLoader.buildSupportsCrypto()) {
      try {
        nativeCryptoLoaded = true;
      } catch (Throwable t) {
        LOG.error("failed to load AESDecryptor", t);
      }
    }
  }
  
  public static boolean isNativeCodeLoaded() {
    return nativeCryptoLoaded;
  }

  /**
   * Creates a new compressor.
   * 
   * @param directBufferSize
   *            size of the direct buffer to be used.
   * @throws CryptoException
   */
  public AESDecryptor(CryptoContext cryptoContext, int directBufferSize) throws CryptoException {
    this.cryptoContext = cryptoContext;
    this.directBufferSize = directBufferSize;
    
    if(cryptoContext != null)
      this.key = cryptoContext.getKey();
    
    compressedDirectBuf = ByteBuffer.allocateDirect(directBufferSize);
    uncompressedDirectBuf = ByteBuffer.allocateDirect(directBufferSize - AESConstants.AES_BLOCK_SIZE);
    uncompressedDirectBuf.position(directBufferSize - AESConstants.AES_BLOCK_SIZE);
  }

  /**
   * Sets input data for decompression. This should be called if and only if
   * {@link #needsInput()} returns <code>true</code> indicating that more
   * input data is required. (Both native and non-native versions of various
   * Decompressors require that the data passed in via <code>b[]</code> remain
   * unmodified until the caller is explicitly notified--via
   * {@link #needsInput()}--that the buffer may be safely modified. With this
   * requirement, an extra buffer-copy can be avoided.)
   * 
   * @param b
   *            Input data
   * @param off
   *            Start offset
   * @param len
   *            Length
   */
  @Override
  public synchronized void setInput(byte[] b, int off, int len) {
    if (b == null) {
      throw new NullPointerException();
    }
    if (off < 0 || len < 0 || off > b.length - len) {
      throw new ArrayIndexOutOfBoundsException();
    }

    this.userBuf = b;
    this.userBufOff = off;
    this.userBufLen = len;

    setInputFromSavedData();

    // Reinitialize snappy's output direct-buffer
    uncompressedDirectBuf.limit(directBufferSize - AESConstants.AES_BLOCK_SIZE);
    uncompressedDirectBuf.position(directBufferSize - AESConstants.AES_BLOCK_SIZE);
  }

  /**
   * If a write would exceed the capacity of the direct buffers, it is set
   * aside to be loaded by this function while the compressed data are
   * consumed.
   */
  synchronized void setInputFromSavedData() {
    compressedDirectBufLen = Math.min(userBufLen, directBufferSize);

    // Reinitialize snappy's input direct buffer
    compressedDirectBuf.rewind();
    ((ByteBuffer) compressedDirectBuf).put(userBuf, userBufOff, compressedDirectBufLen);

    // Note how much data is being fed to snappy
    userBufOff += compressedDirectBufLen;
    userBufLen -= compressedDirectBufLen;
  }

  /**
   * Does nothing.
   */
  @Override
  public synchronized void setDictionary(byte[] b, int off, int len) {
    // do nothing
  }

  /**
   * Returns true if the input data buffer is empty and
   * {@link #setInput(byte[], int, int)} should be called to provide more
   * input.
   * 
   * @return <code>true</code> if the input data buffer is empty and
   *         {@link #setInput(byte[], int, int)} should be called in order to
   *         provide more input.
   */
  @Override
  public synchronized boolean needsInput() {
    // Consume remaining compressed data?
    if (uncompressedDirectBuf.remaining() > 0) {
      return false;
    }

    // Check if snappy has consumed all input
    if (compressedDirectBufLen <= 0) {
      // Check if we have consumed all user-input
      if (userBufLen <= 0) {
        return true;
      } else {
        setInputFromSavedData();
      }
    }

    return false;
  }

  /**
   * Returns <code>false</code>.
   * 
   * @return <code>false</code>.
   */
  @Override
  public synchronized boolean needsDictionary() {
    return false;
  }

  /**
   * Returns true if the end of the decompressed data output stream has been
   * reached.
   * 
   * @return <code>true</code> if the end of the decompressed data output
   *         stream has been reached.
   */
  @Override
  public synchronized boolean finished() {
    return (allInputProcessed && uncompressedDirectBuf.remaining() == 0);
  }

  /**
   * Fills specified buffer with uncompressed data. Returns actual number of
   * bytes of uncompressed data. A return value of 0 indicates that
   * {@link #needsInput()} should be called in order to determine if more
   * input data is required.
   * 
   * @param b
   *            Buffer for the compressed data
   * @param off
   *            Start offset of the data
   * @param len
   *            Size of the buffer
   * @return The actual number of bytes of compressed data.
   * @throws IOException
   */
  @Override
  public synchronized int decrypt(byte[] b, int off, int len) throws IOException {
    if (b == null) {
      throw new NullPointerException();
    }
    if (off < 0 || len < 0 || off > b.length - len) {
      throw new ArrayIndexOutOfBoundsException();
    }

    int n = 0;

    // Check if there is uncompressed data
    n = uncompressedDirectBuf.remaining();
    if (n > 0) {
      n = Math.min(n, len);
      ((ByteBuffer) uncompressedDirectBuf).get(b, off, n);
      return n;
    }
    if (compressedDirectBufLen > 0) {
      // Re-initialize the snappy's output direct buffer
      uncompressedDirectBuf.rewind();
      uncompressedDirectBuf.limit(directBufferSize - AESConstants.AES_BLOCK_SIZE);

      // Decompress data
      try {
        n = cipher.doFinal(compressedDirectBuf, compressedDirectBufLen,
            uncompressedDirectBuf);
      } catch (Exception e) {
        throw new IOException(e);
      }

      compressedDirectBuf.clear();
      compressedDirectBufLen = 0;

      if (userBufLen <= 0) {
        allInputProcessed = true;
      }

      // Get atmost 'len' bytes
      n = Math.min(n, len);
      ((ByteBuffer) uncompressedDirectBuf).get(b, off, n);
    }

    return n;
  }

  public synchronized void reset() {
    allInputProcessed = false;
    compressedDirectBufLen = 0;
    uncompressedDirectBuf.limit(directBufferSize - AESConstants.AES_BLOCK_SIZE);
    uncompressedDirectBuf.position(directBufferSize - AESConstants.AES_BLOCK_SIZE);
    userBufOff = userBufLen = 0;
    cipher.reset(null, null);
  }

  @Override
  public void setIV(byte[] iv) {
    if(key == null)
      throw new RuntimeException("No key specified for decryptor.");
    
    if (!initCalled) {
      cipher.init(NativeOpensslAESCipher.Mode.DECRYPT, key.getRawKey(), iv);
      initCalled = true;
    } else {
      cipher.reset(key.getRawKey(), iv);
    }
  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {
    this.cryptoContext = cryptoContext;
    
    if(cryptoContext != null)
      this.key = cryptoContext.getKey();
  }

  @Override
  public CryptoContext getCryptoContext() {
    return cryptoContext;
  }

  @Override
  public Key getKey() {
    return key;
  }

  @Override
  public void setKey(Key key) {
    this.key = key;
  }
}
