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
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.Key;

/**
 *  Firstly do compression, the compression block size is 
 *  decided by the compressor buffer size.
 *  Then do encryption, and the structure is as follow:
 *  +----------------------------------------------------------------------------------------------------+
    | 4 byte compressed size  |  compressed data    | 4 byte compressed size  | compressed data  | ...   |
    +----------------------------------------------------------------------------------------------------+
 * 
 *
 */
public abstract class BlockEncryptorWithCompressor extends BlockEncryptor{
  final protected BlockEncryptor encryptor;
  final protected Compressor compressor;
  final private int MAX_INPUT_SIZE;
  final private int COMPRESS_BUFFER_SIZE;
  final private int COMPRESS_MAX_INPUT_SIZE;
  //To indicate whether the compressor can buffer the input itself
  final private boolean compressorSelfBuffer; 
  private ByteBuffer buffer;
  private ByteBuffer compressedBuffer;
  private int nBytesRead = 0;
  private int nCachedBytesRead = 0;
  private int nBytesWritten = 0;
  private boolean finish = false;
  private boolean finished = false;
  private boolean needsInputs = true;
  private boolean inputCompressFailed = false;
  private int intSize = Integer.SIZE/Byte.SIZE;

  public BlockEncryptorWithCompressor(BlockEncryptor encryptor,  
      Compressor compressor, int encryptorBlockSize, int encryptorOverhead){
    this.encryptor = encryptor;
    this.compressor = compressor;
    compressorSelfBuffer = false;
    MAX_INPUT_SIZE = encryptorBlockSize - encryptorOverhead;
    COMPRESS_BUFFER_SIZE = Math.min(64 * 1024, MAX_INPUT_SIZE - intSize);
    COMPRESS_MAX_INPUT_SIZE = COMPRESS_BUFFER_SIZE - (COMPRESS_BUFFER_SIZE/6 + 32);
    if(!compressorSelfBuffer){
      buffer = ByteBuffer.allocate(COMPRESS_MAX_INPUT_SIZE);
      buffer.limit(0);
    }
    compressedBuffer = ByteBuffer.allocate(intSize + COMPRESS_BUFFER_SIZE);
    compressedBuffer.limit(0);
  }

  public BlockEncryptorWithCompressor(BlockEncryptor encryptor,
      Compressor compressor, int encryptorBlockSize, int encryptorOverhead,
      int compressorBufferSize, int compressorOverhead, boolean compressorSelfBuffer){
    this.encryptor = encryptor;
    this.compressor = compressor;
    this.compressorSelfBuffer = compressorSelfBuffer;
    MAX_INPUT_SIZE = encryptorBlockSize - encryptorOverhead;
    COMPRESS_BUFFER_SIZE = Math.min(compressorBufferSize, MAX_INPUT_SIZE - intSize);
    COMPRESS_MAX_INPUT_SIZE = COMPRESS_BUFFER_SIZE - compressorOverhead;
    if(!compressorSelfBuffer){
      buffer = ByteBuffer.allocate(COMPRESS_MAX_INPUT_SIZE);
      buffer.limit(0);
    }
    compressedBuffer = ByteBuffer.allocate(intSize + COMPRESS_BUFFER_SIZE);
    compressedBuffer.limit(0);
  }

  public abstract int getStreamHeaderLength();
  public abstract byte[] getStreamHeader();

  @Override
  public int encrypt(byte[] b, int off, int len) throws IOException {
    if (b == null) {
      throw new NullPointerException();
    } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length)) {
      throw new IndexOutOfBoundsException();
    } else if (len == 0) {
      return 0;
    }
    
    if(inputCompressFailed){
      throw new IOException("There is exception when compressing the input");
    }
    
    encryptor.finish();
    int n = encryptor.encrypt(b, off, len);
    nBytesWritten += n;
    
    if(encryptor.finished()){
      encryptor.reset();
      nBytesRead = nCachedBytesRead;
      nCachedBytesRead = 0;
      if(flushDataToEncryptor() == 0){
        finished = true;
      }
      
      needsInputs = true;
    } 
    
    return n;
  }

  @Override
  public void setIV(byte[] iv) {
    encryptor.setIV(iv);
  }
  
  private int getCompressorBytesRead(){
    return compressorSelfBuffer ? (int)compressor.
        getBytesRead() : (buffer.limit() - buffer.position());
  }

  @Override
  public void setInput(byte[] b, int off, int len) {
    if (b == null) {
      throw new NullPointerException();
    }
    if (off < 0 || len < 0 || off > b.length - len) {
      throw new ArrayIndexOutOfBoundsException();
    }
    finished = false;
    
    int toConsumed = len;
    if(compressor != null){
      /*
       * for the input data, we compress it firstly, then 
       * we can decide how much data can be put into the encryptor.
       * Since maybe large input can be compressed to small output,
       * the input data of encryptor should be as much as possible.
       */
      while(toConsumed > 0){
        int availableInCompressor = COMPRESS_MAX_INPUT_SIZE 
            - getCompressorBytesRead();
        if(toConsumed >= availableInCompressor){
          //do compression immediately
          writeToBuffer(b, off+len-toConsumed, availableInCompressor);
          toConsumed -= availableInCompressor;
          int toCompress = getCompressorBytesRead();
          
          int n = 0;
          try{
            n = compressBufferData();
          } catch (IOException e){
            inputCompressFailed = true;
            return;
          }
          
          if(n > 0){ 
            int availableInEncryptor = MAX_INPUT_SIZE - 
                (int)encryptor.getBytesRead();
            if(intSize + n <= availableInEncryptor){ //setInput the result to encryptor
              encryptor.setInput(compressedBuffer.array(), 0, intSize + n);
              /*
               * since we add the compressed result to encryptor,
               * we need to remove it from the buffer.
               */
              compressedBuffer.clear();
              compressedBuffer.limit(0);
              if(n == availableInEncryptor){
                /*
                 * we got enough input data for encryptor,
                 * then we should tell the caller he can do encryption now. 
                 */
                needsInputs = false;
              }
              nBytesRead += toCompress;
            } else { //n > availableInEncryptor
              needsInputs = false;
              nCachedBytesRead += toCompress;
            }
          }
        } else { //toConsumed < availableInCompressor
          writeToBuffer(b, off+len-toConsumed, toConsumed);
          toConsumed = 0;
        }
      }
    } else { //no compressor
      int availableInEncryptor = MAX_INPUT_SIZE - 
          (int)encryptor.getBytesRead();
      if(toConsumed < availableInEncryptor){
        encryptor.setInput(b, off, toConsumed);
        nBytesRead += toConsumed;
      } else { //toConsumed >= availableInEncryptor
        needsInputs = false;
        
        if(availableInEncryptor > 0){
          encryptor.setInput(b, off, availableInEncryptor);
          nBytesRead += availableInEncryptor;
        }
        
        if(toConsumed > availableInEncryptor){ //cache the remaining data of 'b'
          int limit = compressedBuffer.limit();
          if(limit + toConsumed - availableInEncryptor > compressedBuffer.capacity()){
            throw new BufferOverflowException();
          }
          compressedBuffer.limit(limit + toConsumed - availableInEncryptor);
          System.arraycopy(b, off + availableInEncryptor, 
              compressedBuffer.array(), limit, toConsumed - availableInEncryptor);
          compressedBuffer.position(0);
          
          nCachedBytesRead += toConsumed - availableInEncryptor;
        }
      }
    }
  }
  
  public int getSafeInputSize(){
    return COMPRESS_MAX_INPUT_SIZE;
  }
  
  private void writeToBuffer(byte[] b, int off, int len){
    if(compressorSelfBuffer){
      compressor.setInput(b, off, len);
    } else {
      int limit = buffer.limit();
      if(limit + len > buffer.capacity()){
        throw new BufferOverflowException();
      }
      buffer.limit(limit + len);
      System.arraycopy(b, off, buffer.array(), limit, len);
    }
  }
  
  private int compressBufferData() throws IOException{
    if(!compressorSelfBuffer){
      int pos = buffer.position();
      int limit = buffer.limit();
      compressor.setInput(buffer.array(), pos, limit);
      buffer.clear();
      buffer.limit(0);
    }
    
    if(compressedBuffer.remaining() > 0){
      throw new IOException("The lastest compressed data has not been read out");
    }
    compressor.finish();   
    /*
     * add the compressed result to buffer
     */
    int n = compressor.compress(compressedBuffer.array(), intSize, COMPRESS_BUFFER_SIZE);
    byte[] bytesN = int2Bytes(n); //write the compressed block size
    System.arraycopy(bytesN, 0, compressedBuffer.array(), 0, intSize);
    compressedBuffer.limit(intSize + n);
    compressor.reset();
    
    return n;
  }
  
  private int flushDataToEncryptor(){
    int compressedBufferSize = compressedBuffer.limit() 
        - compressedBuffer.position();
    if(compressedBufferSize > 0){
      encryptor.setInput(compressedBuffer.array(), 
          compressedBuffer.position(), compressedBufferSize);
      compressedBuffer.clear();
      compressedBuffer.limit(0);
    }
    
    return compressedBufferSize;
  }

  @Override
  public void finish() {
    flushDataToEncryptor();
    
    if(compressor != null && !compressor.finished()){
      int toCompress = getCompressorBytesRead();
      /*
       * If there is some uncompressed data 
       * when finishing, we should compress it firstly and 
       * then put all the data in buffer to encryptor.
       */
      try {
        if(toCompress > 0){
          int n = compressBufferData();
          if(n > 0){
            int availableInEncryptor = MAX_INPUT_SIZE - 
                (int)encryptor.getBytesRead();
            if(n <= availableInEncryptor){
              flushDataToEncryptor();
              nBytesRead += toCompress;
            } else {
              nCachedBytesRead += toCompress;
            }
          }
        }
      } catch (IOException e) {
        inputCompressFailed = true;
        return;
      }
    }
    
    finish = true;
  }

  @Override
  public boolean finished() {
    return finish && finished;
  }

  @Override
  public long getBytesRead() {
    return nBytesRead;
  }

  @Override
  public long getBytesWritten() {
    return nBytesWritten;
  }

  @Override
  public boolean needsInput() {
    return needsInputs;
  }

  @Override
  public void reset() {	
    encryptor.reset();
    if(compressor != null){
      compressor.reset();
    }
    if(!compressorSelfBuffer){
      buffer.clear();
      buffer.limit(0);
    }
    compressedBuffer.clear();
    compressedBuffer.limit(0);
    nBytesRead = 0;
    nBytesWritten = 0;
    finish = false;
    finished = false;
    inputCompressFailed = false;
  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {
    encryptor.setCryptoContext(cryptoContext);
  }

  @Override
  public CryptoContext getCryptoContext() {
    return encryptor.getCryptoContext();
  }
  
  @Override
  public Key getKey() {
    return encryptor.getKey();
  }
  
  @Override
  public void setKey(Key key) {
    encryptor.setKey(key);
  }

  private byte[] intBytes = new byte[4];
  private byte[] int2Bytes(int v) {
    intBytes[0] = (byte) ((v >>> 24) & 0xFF);
    intBytes[1] = (byte) ((v >>> 16) & 0xFF);
    intBytes[2] = (byte) ((v >>> 8) & 0xFF);
    intBytes[3] = (byte) ((v >>> 0) & 0xFF);

    return intBytes;
  }
}
