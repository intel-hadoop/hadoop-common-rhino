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

package org.apache.hadoop.io.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;

import junit.framework.TestCase;

import org.junit.Test;

public class TestKey extends TestCase {
  
  /**
   * Test new key
   */
  @Test(timeout=15000)
  public void testKey() throws IOException {
    byte[] rawKey = new byte[16];
    for(int i = 0; i < rawKey.length; i++) {
      rawKey[i] = (byte)i;
    }
    
    Key key = new Key(Key.KeyType.SYMMETRIC_KEY, Key.AES, 128, "RAW", rawKey);
    
    assertTrue(key.getKeyType() == Key.KeyType.SYMMETRIC_KEY);
    assertTrue("AES".equals(key.getCryptographicAlgorithm()));
    assertTrue(128 == key.getCryptographicLength());
    assertTrue("RAW".equals(key.getFormat()));
    
    byte[] raw = key.getRawKey();
    assertTrue(16 == raw.length);
    for(int i = 0; i < raw.length; i++) {
      assertTrue(i == raw[i]);
    }
    
  }
  
  /**
   * Test the serialization and deserialization of the key
   */
  @Test(timeout=15000)
  public void testKeySerializeDeserialize() throws IOException {
    byte[] rawKey = new byte[16];
    for(int i = 0; i < rawKey.length; i++) {
      rawKey[i] = (byte)i;
    }
    
    Key key = new Key(Key.KeyType.SYMMETRIC_KEY, Key.AES, 128, "RAW", rawKey);
    
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    DataOutput out = new DataOutputStream(os);
    key.write(out);
    os.flush();
    
    ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
    DataInput in = new DataInputStream(is);
    
    Key keyNew = new Key();
    keyNew.readFields(in);
    
    assertTrue(keyNew.getKeyType() == Key.KeyType.SYMMETRIC_KEY);
    assertTrue("AES".equals(keyNew.getCryptographicAlgorithm()));
    assertTrue(128 == keyNew.getCryptographicLength());
    assertTrue("RAW".equals(keyNew.getFormat()));
    
    byte[] raw = keyNew.getRawKey();
    assertTrue(16 == raw.length);
    for(int i = 0; i < raw.length; i++) {
      assertTrue(i == raw[i]);
    }
  }
}
