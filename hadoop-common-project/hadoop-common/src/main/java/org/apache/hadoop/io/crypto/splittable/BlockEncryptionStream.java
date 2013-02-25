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
import java.io.OutputStream;
import java.nio.ByteBuffer;

import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.KeyProfile;
import org.apache.hadoop.io.crypto.KeyProfileResolver;

/**
 *   Write the input data to blocks.
 * 
 *   File structure:
     +----------------------------------------------+
     | block      | block     | block     | ...     |
     +----------------------------------------------+
     
     block structure :
     +----------------------------------------------------------------------------------------------------+
     | 16 byte sync mark | block header | algorithm header | 4 byte original size | 4 byte encrypted size |
     +----------------------------------------------------------------------------------------------------+
     |   encryption data ...                                                                              |
     +----------------------------------------------------------------------------------------------------+
     
     encryption data structure:
     +----------------------------------------------------------------------------------------------------+
     | 4 byte compressed size  |  compressed data    | 4 byte compressed size  | compressed data  | ...   |
     +----------------------------------------------------------------------------------------------------+
 */
public abstract class BlockEncryptionStream extends CompressionOutputStream {
  protected BlockEncryptorWithCompressor encryptorWithCompressor;
  private ByteBuffer buffer; //buffer for the encrypted data
  private int blockSize;
  
  private static final int VERSION = 1;
  
  private boolean keyUpdated = false;
  private byte[] extension = null;

  public BlockEncryptionStream(OutputStream out, 
      BlockEncryptorWithCompressor encryptorWithCompressor, int blockSize){
    super(out);
    this.encryptorWithCompressor = encryptorWithCompressor;
    buffer = ByteBuffer.allocate(blockSize);
    this.blockSize = blockSize;
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

    int start = off;
    int end = off + len;
    int inputSize = encryptorWithCompressor.getSafeInputSize(); //set the input Size to a safe size
    while(start < end){
      int n = end - start > inputSize ? inputSize : (end-start);
      encryptorWithCompressor.setInput(b, start, n);
      if(!encryptorWithCompressor.needsInput()){
        writeBlock();
      }
      start += n;
    }
  }

  /**
   * write a block
   */
  private void writeBlock() throws IOException {
    if(encryptorWithCompressor.getBytesRead() == 0){
      return;
    }
    //write sync mark
    writeSyncMark();
    //block header
    writeBlockHeader();
    //algorithm header
    writeAlgHeader();
    
    //write original size
    rawWriteInt((int)encryptorWithCompressor.getBytesRead());

    //encrypt the block data
    buffer.clear();
    int n = encryptorWithCompressor.encrypt(buffer.array(), 0, blockSize);

    //write encrypted size
    rawWriteInt(n);
    //write encrypted data
    out.write(buffer.array(), 0, n);
  }
  
  private void writeSyncMark() throws IOException {
    out.write(CryptoSplittableConstants.SYNC_MARK);
  }
  
  private void writeBlockHeader() throws IOException {
    //version
    out.write(int2Bytes(VERSION));
    
    //key profile if has
    writeKeyProfile();
    
    //extension, this is length of the extension field 
    writeExtension();
  }
  
  private void writeKeyProfile() throws IOException {
    KeyProfile keyProfile = getKeyProfile();
    if(keyProfile != null &&
        keyProfile.isValid()) {
      //write key profile data length and data
      byte[] data = keyProfile.getData();
      if(data.length > CryptoSplittableConstants.MAX_HEADER_FIELD_SIZE)
        throw new IOException("Block header field size exceeds the limit(4K).");
      
      rawWriteInt(data.length);
      out.write(data);
      
      if(!keyUpdated) {
        keyUpdated = true;
        
        try {
          updateKey(keyProfile);
        } catch(CryptoException e) {
          throw new IOException("Error happened while trying to resolve key profile.", e);
        }
      }
    } else {
      //no key profile
      rawWriteInt(0);
    }
  }
  
  private void writeExtension() throws IOException {
    if(extension == null) {
      //no extension data
      rawWriteInt(0);
    } else {
      //write extension data length and data
      if(extension.length > CryptoSplittableConstants.MAX_HEADER_FIELD_SIZE)
        throw new IOException("Block header field size exceeds the limit(4K).");
      
      rawWriteInt(extension.length);
      out.write(extension);
    }
  }

  protected abstract void writeAlgHeader() throws IOException;

  @Override
  public void finish() throws IOException {
    encryptorWithCompressor.finish();
    while(!encryptorWithCompressor.finished()
        && encryptorWithCompressor.getBytesRead() > 0){
      writeBlock(); //write the remaining block
    }
  }

  @Override
  public void resetState() throws IOException {
    keyUpdated = false;
    buffer.clear();
    encryptorWithCompressor.reset();
  }

  private byte[] oneByte = new byte[1];
  @Override
  public void write(int b) throws IOException {
    oneByte[0] = (byte)(b & 0xff);
    write(oneByte, 0, oneByte.length);
  }

  protected final void rawWriteInt(int v) throws IOException {
    out.write((v >>> 24) & 0xFF);
    out.write((v >>> 16) & 0xFF);
    out.write((v >>> 8) & 0xFF);
    out.write((v >>> 0) & 0xFF);
  }
  
  private byte[] intBytes = new byte[4];
  protected byte[] int2Bytes(int v) {
    intBytes[0] = (byte) ((v >>> 24) & 0xFF);
    intBytes[1] = (byte) ((v >>> 16) & 0xFF);
    intBytes[2] = (byte) ((v >>> 8) & 0xFF);
    intBytes[3] = (byte) ((v >>> 0) & 0xFF);

    return intBytes;
  }
  
  protected KeyProfile getKeyProfile() {
    CryptoContext cryptoContext = encryptorWithCompressor.getCryptoContext();
    if(cryptoContext == null)
      return null;
    
    return cryptoContext.getKeyProfile();
  }
  

  protected KeyProfileResolver getKeyProfileResolver(){
    CryptoContext cryptoContext = encryptorWithCompressor.getCryptoContext();
    if(cryptoContext == null)
      return null;
    
    return cryptoContext.getKeyProfileResolver();
  }
  
  protected void updateKey(KeyProfile keyProfile) throws CryptoException {
    if(keyProfile == null)
      return;
    
    KeyProfileResolver resolver = getKeyProfileResolver();
    if(resolver == null)
      return;
    
    Key key = resolver.resolve(keyProfile);
    if(key == null)
      return;
      
    encryptorWithCompressor.setKey(key);
  }
  

}
