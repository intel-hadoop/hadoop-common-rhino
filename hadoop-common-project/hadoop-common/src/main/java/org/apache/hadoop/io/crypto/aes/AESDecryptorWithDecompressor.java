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

import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.splittable.BlockDecryptor;
import org.apache.hadoop.io.crypto.splittable.BlockDecryptorWithDecompressor;

/**
 *  The AES stream header structure is as follow:
 *  +-----------------------------------------------------------+
    | aes crypto graphic length  |  1 byte 'compressed' flag    | 
    +-----------------------------------------------------------+
 *
 */
public class AESDecryptorWithDecompressor extends BlockDecryptorWithDecompressor {

  public AESDecryptorWithDecompressor(BlockDecryptor decryptor, 
      Decompressor decompressor, int blockSize){
    super(decryptor, decompressor, blockSize);
  }

  @Override
  public void setStreamHeader(byte[] header) throws IOException {
    if(header == null || header.length != 5){
      throw new IOException("Incorrect stream header");
    }
    
    Key key = decryptor.getKey();
    if(key == null) {
      throw new IOException("No key specified for decryptor.");
    }
    
    int keyLength = rawReadInt(header);
    boolean compressed = header[4] == 0x01 ? true : false;
    if(keyLength != decryptor.getKey().getCryptographicLength()){
      throw new IOException("Dismatch key length.");
    }

    if(!compressed){
      decompressor = null;
    }
  }

  private int rawReadInt(byte[] b) {
    if(b == null || b.length < 4){
      return 0;
    }
    int ch1 = b[0] & 0xFF;
    int ch2 = b[1] & 0xFF;
    int ch3 = b[2] & 0xFF;
    int ch4 = b[3] & 0xFF;
    return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
  }
}
