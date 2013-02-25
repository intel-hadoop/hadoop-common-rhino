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

import java.nio.ByteBuffer;

import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.crypto.splittable.BlockEncryptor;
import org.apache.hadoop.io.crypto.splittable.BlockEncryptorWithCompressor;

/**
 *  The AES stream header structure is as follow:
 *  +-----------------------------------------------------------+
    | aes crypto graphic length  |  1 byte 'compressed' flag    | 
    +-----------------------------------------------------------+
 *
 */
public class AESEncryptorWithCompressor extends BlockEncryptorWithCompressor{
  private ByteBuffer headerBuffer;

  public AESEncryptorWithCompressor(BlockEncryptor encryptor,  
      Compressor compressor, int encryptorBlockSize, int encryptorOverhead){
    super(encryptor, compressor, encryptorBlockSize, encryptorOverhead);
    headerBuffer = ByteBuffer.allocate(AESConstants.AES_STREAM_HEADER_LENGTH);
  }
  
  public AESEncryptorWithCompressor(BlockEncryptor encryptor,  
      Compressor compressor, int encryptorBlockSize, int encryptorOverhead,  
      int compressorBufferSize, int compressorOverhead, boolean compressorSelfBuffer){
    super(encryptor, compressor, encryptorBlockSize, encryptorOverhead, 
        compressorBufferSize, compressorOverhead, compressorSelfBuffer);
    headerBuffer = ByteBuffer.allocate(AESConstants.AES_STREAM_HEADER_LENGTH);
  }
  
  @Override
  public int getStreamHeaderLength() {
    return AESConstants.AES_STREAM_HEADER_LENGTH;
  }

  @Override
  public byte[] getStreamHeader() {
    headerBuffer.clear();
    int keyLength = encryptor.getKey().getCryptographicLength();
    headerBuffer.putInt(keyLength);
    byte compressed = compressor != null ? (byte)0x01 : (byte)0x00;
    headerBuffer.put(compressed);
    return headerBuffer.array();
  }
}
