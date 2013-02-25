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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.crypto.Encryptor;
import org.apache.hadoop.io.crypto.Key;

public abstract class BlockEncryptor implements Encryptor {

  /**
   * @deprecated Use encrypt instead.
   */
  @Override
  @Deprecated
  public final int compress(byte[] b, int off, int len) throws IOException {
    return encrypt(b, off, len);
  }

  @Override
  public void setDictionary(byte[] b, int off, int len) {
    // nop
  }

  @Override
  public void reinit(Configuration conf) {
    // nop
  }

  @Override
  public void end() {
    // nop
  }

  public abstract int encrypt(byte[] b, int off, int len) throws IOException;

  /**
   * if key == null, then key is unchanged. if iv == null, then iv is
   * unchanged.
   */
  public abstract void setIV(byte[] iv);
  
  /**
   * Set the effect encryption key 
   */
  public abstract void setKey(Key key);
  
  /**
   * Get the encryption key in effect
   */
  public abstract Key getKey();

  /**
   * reset the encryptor, the key and iv will keep unchanged.
   */
  public abstract void reset();

  public abstract void setInput(byte[] b, int off, int len);

  public abstract void finish();

  public abstract boolean finished();

  public abstract long getBytesRead();

  public abstract long getBytesWritten();

  public abstract boolean needsInput();
}
