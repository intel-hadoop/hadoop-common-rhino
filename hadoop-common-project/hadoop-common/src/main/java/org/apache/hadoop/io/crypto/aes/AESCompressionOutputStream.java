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
import java.io.OutputStream;

import org.apache.hadoop.io.crypto.aes.AESConstants;
import org.apache.hadoop.io.crypto.aes.AESUtil;
import org.apache.hadoop.io.crypto.splittable.BlockEncryptionStream;
import org.apache.hadoop.io.crypto.splittable.BlockEncryptorWithCompressor;

/**
 *  The AES algorithm header structure is as follow:
 *  +-----------------------------------------------------------------+
    | 4 byte stream header length  |  stream header    | 16 byte IV   | 
    +-----------------------------------------------------------------+
 * 
 */
public class AESCompressionOutputStream extends BlockEncryptionStream {
  private final byte[] iv = new byte[AESConstants.IV_LENGTH];

  public AESCompressionOutputStream(OutputStream out, 
      BlockEncryptorWithCompressor encryptorWithCompressor, int blockSize){
    super(out, encryptorWithCompressor, blockSize);
    AESUtil.randomBytes(iv);
  }

  @Override
  protected void writeAlgHeader() throws IOException {
    if(!(encryptorWithCompressor instanceof AESEncryptorWithCompressor)){
      throw new IOException("Incorrect encryptor is used");
    }
    
    AESEncryptorWithCompressor aes = (AESEncryptorWithCompressor)encryptorWithCompressor;

    //stream header
    out.write(int2Bytes(aes.getStreamHeaderLength()));
    out.write(aes.getStreamHeader());
    
    //iv
    incrementIv();  
    out.write(iv);
    aes.setIV(iv);		
  }

  /**
   * Increment IV for encryption
   */
  private final void incrementIv(){
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
}
