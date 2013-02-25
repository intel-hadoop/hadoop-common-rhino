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

import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.splittable.BlockDecryptor;

public class FakeDecryptor extends BlockDecryptor {
  boolean finish;
  boolean finished;
  int nread;
  int nwrite;

  ByteBuffer userBuf;
  XOR xor;
  private int maxOuputSize;

  public FakeDecryptor(String key, int maxOuputSize) {
    xor = new XOR(key.getBytes()[0]);
    this.maxOuputSize = maxOuputSize;
    userBuf = ByteBuffer.allocate(maxOuputSize);
    userBuf.limit(0);
  }

  @Override
  public int decrypt(byte[] b, int off, int len) throws IOException {
    int bufSize = userBuf.limit() - userBuf.position();
    int n = Math.min(len, bufSize);
    n = Math.min(maxOuputSize, n);
    if (userBuf != null && b != null) {
      System.arraycopy(userBuf.array(), userBuf.position(), b, off, n);
      xor.xor(b, off, n);
    }
    userBuf.position(userBuf.position() + n);
    nwrite += n;

    bufSize = userBuf.limit() - userBuf.position();
    if (bufSize <= 0)
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
    return userBuf.limit() < userBuf.capacity();
  }

  @Override
  public void reset() {
    finish = false;
    finished = false;
    nread = 0;
    nwrite = 0;
    userBuf.clear();
    userBuf.limit(0);
  }

  @Override
  public void setDictionary(byte[] b, int off, int len) {
    // nop
  }

  @Override
  public void setInput(byte[] b, int off, int len) {
    nread += len;
    if (userBuf.limit() + len > userBuf.capacity()) {
      throw new BufferOverflowException();
    }
    int oldLimit = userBuf.limit();
    userBuf.limit(oldLimit + len);
    System.arraycopy(b, off, userBuf.array(), oldLimit, len);
  }

  @Override
  public int getRemaining() {
    return 0;
  }

  @Override
  public void setIV(byte[] iv) {
    // TODO Auto-generated method stub

  }

  @Override
  public void setCryptoContext(CryptoContext cryptoContext) {
    // TODO Auto-generated method stub

  }

  @Override
  public CryptoContext getCryptoContext() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public void setKey(Key key) {
    // TODO Auto-generated method stub

  }

  @Override
  public Key getKey() {
    // TODO Auto-generated method stub
    return null;
  }

}
