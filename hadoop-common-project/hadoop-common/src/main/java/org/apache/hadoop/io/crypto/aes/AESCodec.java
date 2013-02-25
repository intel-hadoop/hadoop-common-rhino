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
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.fs.Seekable;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.compress.SnappyCodec;
import org.apache.hadoop.io.compress.SplitCompressionInputStream;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.splittable.SplittableCryptoCodec;
import org.apache.hadoop.util.NativeCodeLoader;
import org.apache.hadoop.util.ReflectionUtils;

/**
 * Implements AES encryption and decryption. A compressor codec 
 * can be configured being used before encryption, for example, SnappyCodec. 
 * OpenSSL is used as native AES library. To get a good performance, it's 
 * better to use openssl 1.0.1c and run on AES-NI enabled servers.
 */
public class AESCodec implements SplittableCryptoCodec, Configurable {
  private static final Log LOG = LogFactory.getLog(AESCodec.class);

  public static final String AES_DEFAULT_EXT = ".intel_aes";

  private Configuration conf;
  private CryptoContext cryptoContext;
  
  private int DEFAULT_BLOCK_SIZE = 0x40000;
  private int blockSize = DEFAULT_BLOCK_SIZE;
  private CompressionCodec compressionCodec = null;
  
  private int DEFAULT_COMPRESSOR_BUFFER_SIZE = 64 * 1024;
  private int compressorBufferSize = DEFAULT_COMPRESSOR_BUFFER_SIZE;
  private int DEFAULT_COMPRESSOR_OVERHEAD = DEFAULT_COMPRESSOR_BUFFER_SIZE/6 + 32;
  private int compressorOverhead = DEFAULT_COMPRESSOR_OVERHEAD;
  private boolean compressorSelfBuffer = false;
  
  /**
   * Are the native crypto libraries loaded & initialized?
   */
  public static void checkNativeCodeLoaded() {
    if (!NativeCodeLoader.isNativeCodeLoaded()) {
      throw new RuntimeException("Native-hadoop library was not loaded.");
    }
    if (!NativeCodeLoader.buildSupportsCrypto()) {
      throw new RuntimeException("Native crypto library not available: " +
          "this version of libhadoop was built without " +
          "crypto support.");
    }
    if (!AESEncryptor.isNativeCodeLoaded()) {
      throw new RuntimeException("Native crypto library not available: " +
          "AESEncryptor has not been loaded.");
    }
    if (!AESDecryptor.isNativeCodeLoaded()) {
      throw new RuntimeException("Native crypto library not available: " +
          "AESDecryptor has not been loaded.");
    }
  }
  
  public static boolean isNativeCodeLoaded() {
    return AESEncryptor.isNativeCodeLoaded() && 
        AESDecryptor.isNativeCodeLoaded();
  }

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out)
      throws IOException {
    checkNativeCodeLoaded();

    return createOutputStream(out, createCompressor());
  }

  @Override
  public CompressionOutputStream createOutputStream(OutputStream out,
      Compressor compressor) throws IOException {
    checkNativeCodeLoaded();

    if(!(compressor instanceof AESEncryptorWithCompressor)){
      throw new RuntimeException("Incorrect compressor type");
    }

    AESEncryptorWithCompressor aesEncryptorWithCompressor = 
        (AESEncryptorWithCompressor)compressor;


    return new AESCompressionOutputStream(out, aesEncryptorWithCompressor, blockSize);
  }

  @Override
  public Class<? extends Compressor> getCompressorType() {
    checkNativeCodeLoaded();
    return AESEncryptorWithCompressor.class;
  }

  @Override
  public Compressor createCompressor() {
    checkNativeCodeLoaded();
    AESEncryptor encryptor = new AESEncryptor(CryptoContext.makeCopy(cryptoContext), blockSize);
    
    Compressor compressor = null;
    if(compressionCodec != null){
      compressor = compressionCodec.createCompressor();
    }

    return new AESEncryptorWithCompressor(encryptor, compressor, blockSize, 
        AESConstants.AES_BLOCK_SIZE, compressorBufferSize, compressorOverhead, compressorSelfBuffer);
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in)
      throws IOException {
    checkNativeCodeLoaded();

    return createInputStream(in, createDecompressor());
  }

  @Override
  public CompressionInputStream createInputStream(InputStream in,
      Decompressor decompressor) throws IOException {
    checkNativeCodeLoaded();

    if(!(decompressor instanceof AESDecryptorWithDecompressor)){
      throw new RuntimeException("Incorrect decompressor type");
    }

    AESDecryptorWithDecompressor aesDecryptorWithDecompressor = 
        (AESDecryptorWithDecompressor)decompressor;

    return new AESCompressionInputStream(in, aesDecryptorWithDecompressor, blockSize);
  }

  @Override
  public Class<? extends Decompressor> getDecompressorType() {
    checkNativeCodeLoaded();
    return AESDecryptorWithDecompressor.class;
  }

  @Override
  public Decompressor createDecompressor() {
    checkNativeCodeLoaded();
    try{
      AESDecryptor decryptor = new AESDecryptor(CryptoContext.makeCopy(cryptoContext), blockSize);
      Decompressor decompressor = null;
      if(compressionCodec != null){
        decompressor = compressionCodec.createDecompressor();
      }

      return new AESDecryptorWithDecompressor(decryptor, decompressor, blockSize);
    } catch (Exception e){
      LOG.error(e);
      return null;
    }
  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {
    this.cryptoContext = cryptoContext;
  }

  @Override
  public CryptoContext getCryptoContext() {
    return cryptoContext;
  }

  @Override
  public String getDefaultExtension() {
    return AES_DEFAULT_EXT;
  }

  @Override
  public void setConf(Configuration conf) {
    this.conf = conf;
    blockSize = conf.getInt(CRYPTO_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
    compressorBufferSize = conf.getInt(CRYPTO_COMPRESSOR_BUFFER_SIZE, 
        DEFAULT_COMPRESSOR_BUFFER_SIZE);
    String compressionCodecName = conf.get(CRYPTO_COMPRESSOR);
    if(compressionCodecName != null){
      try {
        @SuppressWarnings("unchecked")
        Class<CompressionCodec> compressClass = 
            (Class<CompressionCodec>)conf.getClassByName(compressionCodecName);
        if (null != compressClass) { 
          compressionCodec = ReflectionUtils.newInstance(compressClass, conf);
          if(compressionCodec instanceof SnappyCodec){
            compressorBufferSize = conf.getInt(
                CommonConfigurationKeys.IO_COMPRESSION_CODEC_SNAPPY_BUFFERSIZE_KEY,
                CommonConfigurationKeys.IO_COMPRESSION_CODEC_SNAPPY_BUFFERSIZE_DEFAULT);
            compressorSelfBuffer = true;
          }
        }
      } catch (ClassNotFoundException e) {
        LOG.error("compressor class not found " + compressionCodecName, e);
      }
    }
    compressorSelfBuffer = conf.getBoolean(CRYPTO_COMPRESSOR_SELF_BUFFER, compressorSelfBuffer);
    compressorOverhead = conf.getInt(CRYPTO_COMPRESSOR_OVERHEAD, compressorBufferSize/6 + 32);
  }

  @Override
  public Configuration getConf() {
    return conf;
  }

  @Override
  public SplitCompressionInputStream createInputStream(
      InputStream seekableIn, Decompressor decompressor, long start,
      long end, READ_MODE readMode) throws IOException {
    checkNativeCodeLoaded();
    if (!(seekableIn instanceof Seekable)) {
      throw new IOException("SeekableIn must be an instance of " +
          Seekable.class.getName());
    }

    ((Seekable)seekableIn).seek(start);

    if(!(decompressor instanceof AESDecryptorWithDecompressor)){
      throw new RuntimeException("Incorrect decompressor type");
    }

    AESDecryptorWithDecompressor decryptorWithDecompressor = 
        (AESDecryptorWithDecompressor)decompressor;

    return new AESCompressionInputStream(seekableIn, decryptorWithDecompressor, start, end, readMode, blockSize);
  }
}
