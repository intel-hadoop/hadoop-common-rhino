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

import java.nio.ByteBuffer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.util.NativeCodeLoader;

final public class NativeOpensslAESCipher {
  private static final Log LOG = LogFactory.getLog(NativeOpensslAESCipher.class.getName());
  
  public enum Mode {
    ENCRYPT(1), DECRYPT(0);

    private int value;

    private Mode(int value) {
      this.value = value;
    }

    public int value() {
      return value;
    }
  };
  
  private static boolean nativeCryptoLoaded = false;
  
  static {
    if (NativeCodeLoader.isNativeCodeLoaded() &&
        NativeCodeLoader.buildSupportsCrypto()) {
      try {
        nativeCryptoLoaded = true;
      } catch (Throwable t) {
        LOG.error("failed to load AESEncryptor", t);
      }
    }
  }
  
  public static boolean isNativeCodeLoaded() {
    return nativeCryptoLoaded;
  }

  private long context = 0;
  private boolean inited = false;

  private native long init(int mode, byte[] key, byte[] iv);

  private native void reset(long context, byte[] key, byte[] iv);

  private native void cleanup(long context);

  private native int doFinal(long context, ByteBuffer input, int inputLength, ByteBuffer output);

  /**
   * Initialize the AESCipher. This method only needs to call once
   * @param mode
   * @param key
   * @param iv
   */
  public void init(Mode mode, byte[] key, byte[] iv) {
    context = init(mode.value, key, iv);
    inited = true;
  }

  public void reset() {
    reset(null, null);
  }

  public void reset(byte[] key, byte[] iv) {
    if (!inited) {
      return;
    }
    reset(context, key, iv);
  }
  
  /**
   * input and output are direct buffer for speed improvement.
   * @param input
   * @param inputLength
   * @param output
   * @return the output length 
   * @throws Exception when error happens
   */
  public int doFinal(ByteBuffer input, int inputLength, ByteBuffer output) throws Exception {
    if (!inited) {
      throw new Exception("Cipher not inited, please call init()");
    }
    output.clear();
    output.limit(0);
    int length = doFinal(context, input, inputLength, output);
    if (0 == length) {
      throw new Exception("Decompressed length is 0!!!");
    }
    output.limit(length);
    return length;
  }

  /**
   * Cleanup the AESCipher. This method only needs to call once
   * @throws Exception
   */
  public void cleanup() throws Exception {
    if (inited) {
      cleanup(context);
      inited = false;
    }
  }
  
  protected void finalize() throws Throwable{
    cleanup();
  }
}
