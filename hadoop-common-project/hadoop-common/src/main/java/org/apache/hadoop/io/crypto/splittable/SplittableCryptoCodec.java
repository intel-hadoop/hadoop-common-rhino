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

import org.apache.hadoop.io.compress.SplittableCompressionCodec;
import org.apache.hadoop.io.crypto.CryptoCodec;

public interface SplittableCryptoCodec extends CryptoCodec, SplittableCompressionCodec {
  /**
   * Optional.  The value should be the full class name of compression codec.
   * Specify the compression codec for AES encryption. If specified, runtime 
   * will do compression before encryption, and if not specified, runtime will only do encryption.
   */
  public static final String CRYPTO_COMPRESSOR = "dfs.crypto.compressor";
  /**
   * Optional, default value: 64KB.
   * The buffer size of compression codec.
   */
  public static final String CRYPTO_COMPRESSOR_BUFFER_SIZE = "dfs.crypto.compressor.buffersize";
  /**
   * Optional, default value: compressorBufferSize/6 + 32.
   * Overhead of compression codec.
   */
  public static final String CRYPTO_COMPRESSOR_OVERHEAD = "dfs.crypto.compressor.overhead";
  /**
   * true or false, indicate whether the compressor can buffer the input itself
   */
  public static final String CRYPTO_COMPRESSOR_SELF_BUFFER = "dfs.crypto.compressor.selfbuffer"; 
  /**
   * Optional,  default value: 256KB.
   * The buffer size of AES Codec. It means runtime will do encryption every CRYPTO_BLOCK_SIZE size data.
   */
  public static final String CRYPTO_BLOCK_SIZE = "dfs.crypto.blocksize"; 
}
