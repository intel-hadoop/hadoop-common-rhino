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

/**
 * <code>KeyProfileResolver</code> is a callback interface for resolving a key profile to a key.
 * It is used associating with {@link KeyProfile}.
 */
public interface KeyProfileResolver {
  /**
   * Method to resolve a key to be used from a key profile.
   * 
   * @param keyProfile The key profile to resolve
   * @return The key resolved.
   * @throws CryptoException if error happens
   */
  Key resolve(KeyProfile keyProfile) throws CryptoException;
}
