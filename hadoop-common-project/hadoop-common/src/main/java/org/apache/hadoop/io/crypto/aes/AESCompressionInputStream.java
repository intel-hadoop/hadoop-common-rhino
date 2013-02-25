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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.apache.hadoop.io.compress.SplittableCompressionCodec.READ_MODE;
import org.apache.hadoop.io.crypto.aes.AESConstants;
import org.apache.hadoop.io.crypto.splittable.BlockDecryptionStream;
import org.apache.hadoop.io.crypto.splittable.BlockDecryptorWithDecompressor;

/**
 *  The AES algorithm header structure is as follow:
 *  +-----------------------------------------------------------------+
    | 4 byte stream header length  |  stream header    | 16 byte IV   | 
    +-----------------------------------------------------------------+
 */
public class AESCompressionInputStream extends BlockDecryptionStream {
  private final byte[] iv = new byte[AESConstants.IV_LENGTH];
  private final byte[] streamHeader = new byte[AESConstants.AES_STREAM_HEADER_LENGTH];
  
  public AESCompressionInputStream(InputStream in, BlockDecryptorWithDecompressor 
      decryptorWithDecompressor, int blockSize) throws IOException{
    super(in, decryptorWithDecompressor, blockSize);
  }

  public AESCompressionInputStream(InputStream seekableIn, 
      BlockDecryptorWithDecompressor decryptorWithDecompressor, 
      long start, long end, READ_MODE readMode, int blockSize) throws IOException{
    super(seekableIn, decryptorWithDecompressor, start, end, readMode, blockSize);
  }

  @Override
  protected void readAlgHeader() throws IOException {
    if(!(decryptorWithDecompressor instanceof AESDecryptorWithDecompressor)){
      throw new IOException("Incorrect decompress is used");
    }
    
    AESDecryptorWithDecompressor aes = 
        (AESDecryptorWithDecompressor)decryptorWithDecompressor;

    int streamHeaderLength = rawReadInt();
    if(streamHeaderLength != AESConstants.AES_STREAM_HEADER_LENGTH){
      throw new IOException("Incorrect stream header length");
    }
    readStreamHeader(streamHeader);
    aes.setStreamHeader(streamHeader);

    readIv(iv);
    aes.setIV(iv);	
  }

  /**
   * read the stream header
   */
  private void readStreamHeader(byte[] streamHeader) throws IOException {
    int nRead = safeRead(in, streamHeader, 0, streamHeader.length);
    if (nRead == -1) {
      throw new EOFException();
    }
  }

  /**
   * Write initialization vector of AES algorithm
   * The IV should be 16 bytes.
   * @param iv
   * @throws IOException
   */
  private void readIv(byte[] iv) throws IOException {
    int nRead = safeRead(in, iv, 0, AESConstants.IV_LENGTH);
    if (nRead == -1) {
      throw new EOFException();
    }
  }
}
