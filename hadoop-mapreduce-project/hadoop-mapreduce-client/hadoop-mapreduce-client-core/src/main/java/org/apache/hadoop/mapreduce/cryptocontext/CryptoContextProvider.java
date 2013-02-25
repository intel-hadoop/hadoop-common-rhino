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

package org.apache.hadoop.mapreduce.cryptocontext;

import org.apache.hadoop.conf.Configurable;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;

/**
 * <code>CryptoContextProvider</code> interface defines the service of getting {@link CryptoContext}
 * according to a context object (Path of the file) and purpose. By using <code>CryptoContextProvider</code>
 * For MapReduce, different processing stages (input, output, and map output) can specify different 
 * <code>CryptoContextProvider</code> for providing different policy of resolving <code>CryptoContext</code> for a file. 
 * A <code>CryptoContextProvider</code> can be configured with parameters and secrets which are serialized
 * into byte array. Both parameters and secrets are stored in Job credentials and distributed to task tracker.
 * The implementation of CryptoContextProvider can choose whether or not to encrypt the secret keys stored
 * in job Credentials.
 */

public interface CryptoContextProvider extends Configurable {
  /**
   * Purpose enumeration for the {@link CryptoContext} retrieving. 
   * <code>ENCRYPTION</code>: retrieving a <code>CryptoContext</code> for encryption purposes.
   * <code>DECRYPTION</code>: retrieving a <code>CryptoContext</code> for deccryption purposes.
   */
  public enum Purpose {
    ENCRYPTION,
    DECRYPTION;
  }
  
  /**
   * Initialize the key provider with the parameters and secrets
   * 
   * @param parameters The parameters for the provider implementation.
   * @param secrets The serialized secrets of the provider implementation.
   * @throws CryptoException if error happens
   */
  void init(byte[] parameters, byte[] secrets) throws CryptoException;
  
  /**
   * Get the {@link CryptoContext} for a specified context and purposes.
   * For MapReduce job, the context is the path object of the file.
   * 
   * @param context The file context for which to retrieve <code>CryptoContext</code> for.
   * @param purpose The current purpose for <code>CryptoContext</code>.
   * @return the <code>CryptoContext</code> object that can be used by <code>CryptoCodec</code>.
   */
  CryptoContext getCryptoContext(Object context, Purpose purpose) throws CryptoException;
  
}
