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

import org.apache.hadoop.io.compress.Decompressor;

/**
 * A fake decompressor, just like FakeCompressor
 * Its input and output is the same.
 */
public class FakeDecompressor implements Decompressor {
  boolean finish;
  boolean finished;
  int nread;
  int nwrite;
  
  byte [] userBuf;
  int userBufOff;
  int userBufLen;

  
  int maxOuputSize = 100;
  
  public FakeDecompressor(int maxOuputSize) {
      this.maxOuputSize = maxOuputSize;
  }   
  
  @Override
  public int decompress(byte[] b, int off, int len) throws IOException {
    int n = Math.min(len, userBufLen);
    n = Math.min(n,  maxOuputSize);
    if (userBuf != null && b != null) {
      System.arraycopy(userBuf, userBufOff, b, off, n);
      new XOR((byte)0x88).xor(b, off,  n);
    }
    userBufOff += n;
    userBufLen -= n;
    nwrite += n;
    
    if (userBufLen <= 0)
      finished = true;
    
    return n;
  }

  @Override
  public void end() {
    // nop
  }

  @Override
  public boolean finished() {
    return finished;
  }

  @Override
  public boolean needsDictionary() {
    return false;
  }

  @Override
  public boolean needsInput() {
    return userBufLen <= 0;
  }

  @Override
  public void reset() {
    finish = false;
    finished = false;
    nread = 0;
    nwrite = 0;
    userBuf = null;
    userBufOff = 0;
    userBufLen = 0;
  }

  @Override
  public void setDictionary(byte[] b, int off, int len) {
    // nop
  }

  @Override
  public void setInput(byte[] b, int off, int len) {
    nread += len;
    userBuf = b;
    userBufOff = off;
    userBufLen = len;
  }

  @Override
  public int getRemaining() {
    return 0;
  }
}
