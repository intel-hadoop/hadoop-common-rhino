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

import org.apache.hadoop.io.crypto.Decryptor;
import org.apache.hadoop.io.crypto.Key;

public abstract class BlockDecryptor implements Decryptor {

  /**
   * @deprecated Use decrypt instead.
   */
  @Override
  @Deprecated
  public int decompress(byte[] b, int off, int len) throws IOException {
    return decrypt(b, off, len);
  }

  public abstract int decrypt(byte[] b, int off, int len) throws IOException;

  /**
   * if iv == null, then iv is unchanged.
   */
  public abstract void setIV(byte[] iv);
  
  /**
   * Set the effect decryption key 
   */
  public abstract void setKey(Key key);
  
  /**
   * Get the decryption key in effect
   */
  public abstract Key getKey();

  /**
   * reset the encryptor, the key and iv will keep unchanged.
   */
  public abstract void reset();

  public int getRemaining() {
    return 0;
  }

  @Override
  public void end() {
    // nop
  }

  @Override
  public void setDictionary(byte[] b, int off, int len) {
    // nop
  }

  @Override
  public boolean needsDictionary() {
    return false;
  }
}
