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

public class CryptoSplittableConstants {
  public static final byte[] SYNC_MARK = { 0x31, 0x41, 0x59, 0x26, 0x53, 0x58, (byte) 0x97,
    (byte) 0x93, 0x23, (byte) 0x84, 0x62, 0x64, 0x33, (byte) 0x83, 0x27, (byte) 0x95 };
  public static final int SYNC_MARK_LENGTH = SYNC_MARK.length;

  public static final int version = 1;
  public static final int VERSION_LENGTH = 4; // size of int
  
  public static final int MAX_HEADER_FIELD_SIZE = 4096; //4K
}
