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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.Arrays;

import org.apache.hadoop.io.Writable;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.util.StringUtils;

/**
 * <code>KeyProfile</code> class for store implementation specific data associate to the Key that used
 * to encrypt the data. The <code>KeyProfile</code> is optional for an implementation.
 * Internally, the key profile wraps a byte array which represents the data.
 */
public class KeyProfile implements Writable {
  private byte[] data;

  /** A new key profile. */
  public KeyProfile() {
  }

  /** A new key profile with specified data. */
  public KeyProfile(byte[] data) {
    this.data = data;
  }

  /** Return the byte data of the key profile. */
  public byte[] getData() {
    return data;
  }

  /** Set the byte data of the key profile. */
  public void setData(byte[] data) {
    this.data = data;
  }

  /** Check whether the key profile is valid or not. */
  public boolean isValid() {
    if(data == null)
      return false;

    return true;
  }

  @Override
  public String toString() {
    if(!isValid())
      return "INVALID KEY PROFILE";

    return StringUtils.byteToHexString(data);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;

    if (!(obj instanceof KeyProfile))
      return false;

    final KeyProfile other = (KeyProfile)obj;

    if(data == null) {
      if(other.data != null)
        return false;
    } else {
      if(!Arrays.equals(data, other.data))
        return false;
    }

    return true;
  }
  
  @Override
  public int hashCode() {
    return super.hashCode();
  }

  @Override
  public void write(DataOutput out) throws IOException {
    if(data == null) {
      WritableUtils.writeVInt(out, 0);
    } else {
      WritableUtils.writeVInt(out, data.length);
      out.write(data);
    }
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    int len = WritableUtils.readVInt(in);
    if(len > 0) {
      byte[] value = new byte[len];
      in.readFully(value);
      data = value;
    } else {
      data = null;
    }
  }

}
