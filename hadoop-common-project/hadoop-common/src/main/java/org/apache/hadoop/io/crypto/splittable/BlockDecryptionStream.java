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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.hadoop.fs.Seekable;
import org.apache.hadoop.io.compress.SplitCompressionInputStream;
import org.apache.hadoop.io.compress.SplittableCompressionCodec.READ_MODE;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.KeyProfile;
import org.apache.hadoop.io.crypto.KeyProfileResolver;

/**
 * in this class, adjust the start and end of the file split.
 * file split will start with syncMark, and end at syncMark.
 */
public abstract class BlockDecryptionStream extends SplitCompressionInputStream {
  byte[] syncMarkBytes = new byte[CryptoSplittableConstants.SYNC_MARK_LENGTH];
  private boolean eof = false;
  private ByteBuffer buffer; //buffer for the encrypted and unencrypted data.
  protected BlockDecryptorWithDecompressor decryptorWithDecompressor;

  private READ_MODE readMode;
  private KMP searcher;
  
  private boolean keyUpdated = false;
  private ByteBuffer fieldBuffer; //buffer for read header related field
  
  private int blockOriginalSize = 0;
  private int nReadFromBlock = 0; 
  private boolean blockFinished = true;

  public BlockDecryptionStream(InputStream in, BlockDecryptorWithDecompressor 
      decryptorWithDecompressor, int blockSize) throws IOException{
    super(in, 0, -1);
    this.decryptorWithDecompressor = decryptorWithDecompressor;
    searcher = new KMP(CryptoSplittableConstants.SYNC_MARK);
    readMode = READ_MODE.BYBLOCK;
    buffer = ByteBuffer.allocate(blockSize);
    buffer.limit(0);
    fieldBuffer = ByteBuffer.allocate(CryptoSplittableConstants.MAX_HEADER_FIELD_SIZE);
    fieldBuffer.limit(0);
  }

  public BlockDecryptionStream(InputStream seekableIn, BlockDecryptorWithDecompressor 
      decryptorWithDecompressor, long start, long end, READ_MODE readMode, int blockSize) throws IOException {
    super(seekableIn, start, end);
    this.decryptorWithDecompressor = decryptorWithDecompressor;
    this.readMode = readMode;
    searcher = new KMP(CryptoSplittableConstants.SYNC_MARK);
    buffer = ByteBuffer.allocate(blockSize);
    buffer.limit(0);
    fieldBuffer = ByteBuffer.allocate(CryptoSplittableConstants.MAX_HEADER_FIELD_SIZE);
    fieldBuffer.limit(0);

    if(start == 0){
      readSyncMark();
      ((Seekable) seekableIn).seek(0);
    }

    long firstSyncMarkOff = getNextSyncMarkOff(seekableIn);
    if(firstSyncMarkOff == -1){
      eof = true;
      setEnd(start);
      return;
    }

    //get the last sync mark off
    long lastSyncMarkOff = getLastSyncMarkOff(end, seekableIn);

    start = start + firstSyncMarkOff;
    ((Seekable) seekableIn).seek(start);
    setStart(start); //adjust the file split start

    end = end + lastSyncMarkOff;
    setEnd(end); //adjust the file split end
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    if (b == null) {
      throw new NullPointerException();
    } else if ((off < 0) || (off > b.length) || (len < 0) || ((off + len) > b.length)) {
      throw new IndexOutOfBoundsException();
    } else if (len == 0) {
      return 0;
    }

    if(eof){
      return -1;
    }

    byte[] buf = buffer.array();
    int bufPos = buffer.position();
    int bufLimit = buffer.limit();
    int bufSize = bufLimit - bufPos;
    if(bufSize >= len){ //read data from buffer
      System.arraycopy(buf, bufPos, b, off, len);
      if(bufSize == len){
        buffer.clear();
        buffer.limit(0);
      } else {
        buffer.position(bufPos + len);
      }

      return len;
    } else if(bufSize > 0){ //read data from buffer
      System.arraycopy(buf, bufPos, b, off, bufSize);
      buffer.clear();
      buffer.limit(0);
      
      return bufSize;
    }
    
    //read data from next block
    int nRead = readNextBlock();
    
    if(nRead == -1){
      return -1;
    }
    
    if(nRead >= len){//here, we got enough data
      buffer.get(b, off, len);
      if(nRead > len){ //cache the remaining data to buffer
        buffer.position(len);
      }
      return len;
    } else {
      buffer.get(b, off, nRead);
      buffer.clear();
      buffer.limit(0);
      
      return nRead;
    }
  }
  
  /**
   * read next block and decrypt it
   * the return value is the read data size
   */
  private int readNextBlock() throws IOException {
    if(blockFinished){
      //read sync mark
      readSyncMark();

      if(eof){
        return -1;
      }

      //block header
      readBlockHeader();
      //algorithm header
      readAlgHeader();
      //read original size
      blockOriginalSize = rawReadInt();
      //read encrypted size
      int encryptedSize = rawReadInt();
      //read encrypted data
      buffer.clear();
      if(safeRead(in, buffer.array(), 0, encryptedSize) != encryptedSize){
        throw new IOException("Can't read enough encrypted data");
      }

      blockFinished = false;
      nReadFromBlock = 0;
      decryptorWithDecompressor.reset();
      decryptorWithDecompressor.setInput(buffer.array(), 0, encryptedSize);
    } 
    
    buffer.clear();
    
    int n = decryptorWithDecompressor.decrypt(buffer.array(), 0, buffer.capacity());
    nReadFromBlock += n;
    buffer.limit(n);
    if(decryptorWithDecompressor.finished()){
      blockFinished = true;
      if(nReadFromBlock != blockOriginalSize){
        throw new  IOException("Bad encrypted data"); 
      }
    }

    return n;
  }
  
  private void readSyncMark() throws IOException{
    int nRead = safeRead(in, syncMarkBytes, 0, CryptoSplittableConstants.SYNC_MARK_LENGTH);
    if (nRead != -1) {
      if (!Arrays.equals(syncMarkBytes, CryptoSplittableConstants.SYNC_MARK)) {
        throw new IOException("Can't find sync mark in the stream");
      }
    } else {
      eof = true;
    }
  }
  
  private void readBlockHeader() throws IOException {
    //version
    rawReadInt();
    
    //read the Key Profile if has
    readKeyProfile();
    
    //read the extension if has
    readExtension();
  }
  
  private void readKeyProfile() throws IOException {
    int length = rawReadInt();
    if(length > 0) {
      if(length > CryptoSplittableConstants.MAX_HEADER_FIELD_SIZE)
        throw new IOException("Block header field size exceeds the limit(4K).");
      
      if(safeRead(in, fieldBuffer.array(), 0, length) != length)
        throw new IOException("Failed to read key profile field in the header.");
      
      //process key profile only once
      if(keyUpdated)
        return;
      
      keyUpdated = true;
      
      //we need to make a copy here
      byte[] data = new byte[length];
      System.arraycopy(fieldBuffer.array(), 0, data, 0, length);
      
      KeyProfile keyProfile = new KeyProfile(data);
      
      try {
        updateKey(keyProfile);
      } catch(CryptoException e) {
        throw new IOException("Error happened while trying to resolve key profile.", e);
      }
    } else {
      //if there is no key profile in data
      //check whether external passed one or not
    
      //process  key profile only once
      if(keyUpdated)
        return;
      
      keyUpdated = true;
      KeyProfile keyProfile = getKeyProfile();
      
      try {
        updateKey(keyProfile);
      } catch(CryptoException e) {
        throw new IOException("Error happened while trying to resolve key profile.", e);
      }
      
    }
  }
  
  private void readExtension() throws IOException {
    
    int length = rawReadInt();
    if(length > 0) {
      if(length > CryptoSplittableConstants.MAX_HEADER_FIELD_SIZE)
        throw new IOException("Block header field size exceeds the limit(4K).");
      
      if(safeRead(in, fieldBuffer.array(), 0, length) != length)
        throw new IOException("Failed to read extension field in the header.");
    }
  }

  /**
   * read enough 'len' data until 'eof'
   */
  protected int safeRead(InputStream in, 
      byte[] buf, int off, int len) throws IOException {
    int nRead = 0;
    while(nRead < len){
      int n = in.read(buf, off + nRead, len - nRead);
      if(nRead == 0 && n == -1){
        return -1;
      } else if(n == -1){
        break;
      } else {
        nRead += n;
      }
    }

    return nRead;
  }

  /**
   * get the next syncMark, the return value is the offset 
   */
  private long getNextSyncMarkOff(InputStream in) throws IOException {
    if (readMode == READ_MODE.BYBLOCK) {     
      long offset = searcher.search(in);
      return offset;
    } else {
      throw new IOException("Only support reading by block");
    }
  }

  /**
   * get the first syncMark after the file split, and adjust the file split end to that position
   */
  private long getLastSyncMarkOff(long end, InputStream in) throws IOException {
    ((Seekable)in).seek(end);
    long lastSyncMarkOff = getNextSyncMarkOff(in);
    if(lastSyncMarkOff == -1){
      int off = 0;
      while(in.read() != -1){
        off++;
      }
      lastSyncMarkOff = off;
    }
    return lastSyncMarkOff;
  }

  protected abstract void readAlgHeader() throws IOException;

  @Override
  public void resetState() throws IOException {
    eof = false;
    keyUpdated = false;
    buffer.clear();
    buffer.limit(0);
    decryptorWithDecompressor.reset();
    if(in instanceof Seekable){
      ((Seekable) in).seek(getAdjustedStart());	
    }
    blockOriginalSize = 0;
    nReadFromBlock = 0; 
    blockFinished = true;
  }

  byte[] oneByte = new byte[1];
  @Override
  public int read() throws IOException {
    return (read(oneByte, 0, oneByte.length) == -1) ? -1 : (oneByte[0] & 0xff);
  }

  /** 
   * read int value from inputstream
   */
  final protected int rawReadInt() throws IOException {
    int b1 = in.read();
    int b2 = in.read();
    int b3 = in.read();
    int b4 = in.read();
    if ((b1 | b2 | b3 | b4) < 0){
      throw new EOFException();
    }    

    return ((b1 << 24) + (b2 << 16) + (b3 << 8) + (b4 << 0));
  }
  
  protected KeyProfile getKeyProfile() {
    CryptoContext cryptoContext = decryptorWithDecompressor.getCryptoContext();
    if(cryptoContext == null)
      return null;
    
    return cryptoContext.getKeyProfile();
  }
  
  protected KeyProfileResolver getKeyProfileResolver(){
    CryptoContext cryptoContext = decryptorWithDecompressor.getCryptoContext();
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
      
    decryptorWithDecompressor.setKey(key);
  }
}
