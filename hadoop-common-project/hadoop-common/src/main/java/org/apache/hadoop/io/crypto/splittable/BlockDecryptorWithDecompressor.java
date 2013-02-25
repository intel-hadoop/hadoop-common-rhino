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
import java.nio.ByteBuffer;

import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.Key;

public abstract class BlockDecryptorWithDecompressor extends BlockDecryptor {
  final protected BlockDecryptor decryptor;
  protected Decompressor decompressor;
  final private int bufferSize;
  private ByteBuffer buffer;

  public BlockDecryptorWithDecompressor(BlockDecryptor decryptor, 
      Decompressor decompressor, int bufferSize){
    this.decryptor = decryptor;
    this.decompressor = decompressor;
    this.bufferSize = bufferSize;
    buffer = ByteBuffer.allocate(bufferSize);
    buffer.limit(0);
  }

  public abstract void setStreamHeader(byte[] header) throws IOException;

  @Override
  public void setInput(byte[] b, int off, int len) {
    decryptor.setInput(b, off, len);
  }

  @Override
  public boolean needsInput() {
    return decryptor.needsInput() && 
        (decompressor != null && decompressor.needsInput());
  }

  @Override
  public boolean finished() {
    return !buffer.hasRemaining() &&decryptor.finished() 
        && (decompressor == null || (decompressor != null && decompressor.finished()));
  }

  @Override
  public int decrypt(byte[] b, int off, int len) throws IOException {
    if (b == null) {
      throw new NullPointerException();
    } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length)) {
      throw new IndexOutOfBoundsException();
    } else if (len == 0) {
      return 0;
    }

    //do decryption
    int bufSize = buffer.limit() - buffer.position();
    if(bufSize == 0 && !decryptor.finished()){
      buffer.clear();
      int n = decryptor.decrypt(buffer.array(), 0, bufferSize);
      if(!decryptor.finished()){
        throw new IOException("The buffersize of decryptor is too small.");
      }
      buffer.limit(n);
    }

    int l = 0;
    if(decompressor != null){ //do decompression
      int compressedBlockLen = buffer.getInt(); //read compressed block length
      decompressor.reset();
      decompressor.setInput(buffer.array(), buffer.position(), compressedBlockLen);
      l = decompressor.decompress(b, off, len);
      if(!decompressor.finished()){
        throw new IOException("The buffer size of the decompressor is too small.");
      }
      buffer.position(buffer.position() + compressedBlockLen);
    } else {
      l = buffer.limit() - buffer.position();
      buffer.get(b, off, l);
    }

    return l;
  }

  @Override
  public void setIV(byte[] iv) {
    decryptor.setIV(iv);
  }

  @Override
  public void reset() {	
    decryptor.reset();
    if(decompressor != null){
      decompressor.reset();
    }
    buffer.clear();
    buffer.limit(0);
  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {
    decryptor.setCryptoContext(cryptoContext);
  }

  @Override
  public CryptoContext getCryptoContext() {
    return decryptor.getCryptoContext();
  }

  @Override
  public Key getKey() {
    return decryptor.getKey();
  }
  
  @Override
  public void setKey(Key key) {
    decryptor.setKey(key);
  }
    
}
