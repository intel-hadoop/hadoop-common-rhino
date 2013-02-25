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
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.splittable.BlockEncryptor;
import org.apache.hadoop.util.NativeCodeLoader;

public class AESEncryptor extends BlockEncryptor {
  private static final Log LOG = LogFactory.getLog(AESEncryptor.class.getName());

  private NativeOpensslAESCipher cipher = new NativeOpensslAESCipher();
  private boolean initCalled = false;

  private int directBufferSize;
  private ByteBuffer compressedDirectBuf = null;
  private int uncompressedDirectBufLen;
  private ByteBuffer uncompressedDirectBuf = null;
  private byte[] userBuf = null;
  private int userBufOff = 0, userBufLen = 0;
  private boolean finish, allInputProcessed;

  private long bytesRead = 0L;
  private long bytesWritten = 0L;

  private Key key;
  
  private CryptoContext cryptoContext;
  
  private static boolean nativeCryptoLoaded = false;
  
  static {
    if (NativeCodeLoader.isNativeCodeLoaded() &&
        NativeCodeLoader.buildSupportsCrypto()) {
      try {
        nativeCryptoLoaded = true;
      } catch (Throwable t) {
        LOG.error("failed to load AESEncryptor", t);
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
   * @throws Exception
   */
  public AESEncryptor(CryptoContext cryptoContext, int directBufferSize) {
    this.cryptoContext = cryptoContext;
    this.directBufferSize = directBufferSize;
    
    if( cryptoContext != null )
      this.key = cryptoContext.getKey();
    
    uncompressedDirectBuf = ByteBuffer.allocateDirect(directBufferSize - AESConstants.AES_BLOCK_SIZE);
    compressedDirectBuf = ByteBuffer.allocateDirect(directBufferSize);
    compressedDirectBuf.position(directBufferSize);
  }

  /**
   * Sets input data for compression. This should be called whenever
   * #needsInput() returns <code>true</code> indicating that more input data
   * is required.
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

    if (len == 0) {
      return;
    }

    allInputProcessed = false;

    if (len > uncompressedDirectBuf.remaining()) {
      // save data; now !needsInput
      this.userBuf = b;
      this.userBufOff = off;
      this.userBufLen = len;
    } else {
      ((ByteBuffer) uncompressedDirectBuf).put(b, off, len);
      uncompressedDirectBufLen = uncompressedDirectBuf.position();
    }

    bytesRead += len;
  }

  /**
   * If a write would exceed the capacity of the direct buffers, it is set
   * aside to be loaded by this function while the compressed data are
   * consumed.
   */
  synchronized void setInputFromSavedData() {
    if (0 >= userBufLen) {
      return;
    }
    allInputProcessed = false;

    uncompressedDirectBufLen = Math.min(userBufLen, directBufferSize
        - AESConstants.AES_BLOCK_SIZE);
    ((ByteBuffer) uncompressedDirectBuf).put(userBuf, userBufOff, uncompressedDirectBufLen);

    // Note how much data is being fed
    userBufOff += uncompressedDirectBufLen;
    userBufLen -= uncompressedDirectBufLen;
  }

  /**
   * Does nothing.
   */
  @Override
  public synchronized void setDictionary(byte[] b, int off, int len) {
    // do nothing
  }

  /**
   * Returns true if the input data buffer is empty and #setInput() should be
   * called to provide more input.
   * 
   * @return <code>true</code> if the input data buffer is empty and
   *         #setInput() should be called in order to provide more input.
   */
  @Override
  public synchronized boolean needsInput() {
    return compressedDirectBuf.remaining() == 0 && uncompressedDirectBuf.remaining() > 0
        && userBufLen == 0;
  }

  /**
   * When called, indicates that compression should end with the current
   * contents of the input buffer.
   */
  @Override
  public synchronized void finish() {
    finish = true;
  }

  /**
   * Returns true if the end of the compressed data output stream has been
   * reached.
   * 
   * @return <code>true</code> if the end of the compressed data output stream
   *         has been reached.
   */
  @Override
  public synchronized boolean finished() {
    // Check if all uncompressed data has been consumed
    return finish && allInputProcessed && compressedDirectBuf.remaining() == 0;

  }

  /**
   * Fills specified buffer with compressed data. Returns actual number of
   * bytes of compressed data. A return value of 0 indicates that needsInput()
   * should be called in order to determine if more input data is required.
   * 
   * @param b
   *            Buffer for the compressed data
   * @param off
   *            Start offset of the data
   * @param len
   *            Size of the buffer
   * @return The actual number of bytes of compressed data.
   */
  @Override
  public synchronized int encrypt(byte[] b, int off, int len) throws IOException {
    if (b == null) {
      throw new NullPointerException();
    }
    if (off < 0 || len < 0 || off > b.length - len) {
      throw new ArrayIndexOutOfBoundsException();
    }

    // Check if there is compressed data
    int n = compressedDirectBuf.remaining();
    if (n > 0) {
      n = Math.min(n, len);
      ((ByteBuffer) compressedDirectBuf).get(b, off, n);
      bytesWritten += n;
      return n;
    }

    compressedDirectBuf.clear();
    compressedDirectBuf.limit(0);
    if (0 == uncompressedDirectBuf.position()) {
      // No compressed data, so we should have !needsInput or !finished
      setInputFromSavedData();
      if (0 == uncompressedDirectBuf.position()) {
        // Called without data; write nothing
        allInputProcessed = true;
        return 0;
      }
    }

    // Compress data
    try {
      n = cipher
          .doFinal(uncompressedDirectBuf, uncompressedDirectBufLen, compressedDirectBuf);
    } catch (Exception e) {
      throw new IOException(e);
    }
    uncompressedDirectBuf.clear();
    uncompressedDirectBufLen = 0;

    if (0 == userBufLen) {
      allInputProcessed = true;
    }

    // Get atmost 'len' bytes
    n = Math.min(n, len);
    bytesWritten += n;
    compressedDirectBuf.get(b, off, n);

    return n;
  }

  /**
   * Resets compressor so that a new set of input data can be processed.
   */
  @Override
  public synchronized void reset() {
    finish = false;
    allInputProcessed = false;
    uncompressedDirectBuf.clear();
    uncompressedDirectBufLen = 0;
    compressedDirectBuf.clear();
    compressedDirectBuf.limit(0);
    userBufOff = userBufLen = 0;
    bytesRead = bytesWritten = 0L;
    cipher.reset(null, null);

  }

  /**
   * Prepare the compressor to be used in a new stream with settings defined
   * in the given Configuration
   * 
   * @param conf
   *            Configuration from which new setting are fetched
   */

  /**
   * Return number of bytes given to this compressor since last reset.
   */
  @Override
  public synchronized long getBytesRead() {
    return bytesRead;
  }

  /**
   * Return number of bytes consumed by callers of compress since last reset.
   */
  @Override
  public synchronized long getBytesWritten() {
    return bytesWritten;
  }

  @Override
  public void setIV(byte[] iv) {
    if(key == null)
      throw new RuntimeException("No key specified for encryptor.");
    
    if (!initCalled) {
      cipher.init(NativeOpensslAESCipher.Mode.ENCRYPT, key.getRawKey(), iv);
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
