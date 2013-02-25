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

package org.apache.hadoop.mapreduce.cryptocontext.provider;

import java.io.IOException;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.mapred.JobConf;

/**
 * <code>FileMatchCryptoContextProvider</code> provides the ability the select {@link CryptoContext}
 * according to the file path with regular expression matches. The user defines a list of match rules. 
 * If the a path string matches, the corresponding key context will be choose and a key will be resolved
 * for decryption or encryption the file. 
 * Besides the flexibility for choosing different key for different files, The FileMatchCryptoContextProvider 
 * also provides the ability to extended by user to customize how the key is retrieved. Those who want 
 * to customize how the key is retrieved need to override <code>getKey</code> method. By default <code>getKey</code>
 * assumes the {@link KeyContext} stores the raw key data. Users can override the getKey to to retrieve the real key 
 * if the KeyContext store the key reference such as a key id. 
 */

public class FileMatchCryptoContextProvider extends AbstractCryptoContextProvider {
  private byte[] parameters;
  private FileMatches fileMatches;

  @Override
  public void init(byte[] parameters, byte[] secrets) throws CryptoException {
    this.parameters = parameters;

    try {
      fileMatches = FileMatches.from(secrets);
    } catch(IOException e) {
      throw new CryptoException(e);
    }
  }

  protected byte[] getParameters() {
    return parameters;
  }

  /**
   * Override to decide the <code>KeyContext</code> according to file match rules.
   */
  protected KeyContext getKeyContext(Object context, Purpose purpose) throws CryptoException {
    if(fileMatches == null)
      return null;

    if (context == null ||
        !(context instanceof Path)) {
      return fileMatches.getDefaultKeyContext();
    }

    Path file = (Path) context;
    return fileMatches.getMatchedKey(file);
  }

  /**
   * Map a Key Context for a Key if possible
   * 
   * By default getKey assumes the KeyContext stores the raw key context
   * Users can override the map key to to retrieve the real key if the 
   * KeyContext doesn't store the key reference such as a key id.
   */
  protected Key getKey(KeyContext keyContext) throws CryptoException {
    return keyContext.toKey();
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for input files with {@link FileMatches}.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param parameters The parameters for the implementation if has.
   */
  public static void setInputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, byte[] parameters) throws CryptoException {
    setInputCryptoContextProvider(jobConf, FileMatchCryptoContextProvider.class, fileMatches, parameters);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for output files with {@link FileMatches}.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param parameters The parameters for the implementation if has.
   */
  public static void setOutputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, byte[] parameters) throws CryptoException {
    setOutputCryptoContextProvider(jobConf, FileMatchCryptoContextProvider.class, fileMatches, parameters);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for map output files with {@link FileMatches}.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param parameters The parameters for the implementation if has.
   */
  public static void setMapOutputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, byte[] parameters) throws CryptoException  {
    setMapOutputCryptoContextProvider(jobConf, FileMatchCryptoContextProvider.class, fileMatches, parameters);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for input files with {@link FileMatches}.
   * 
   * @param cryptoContextProviderClass The full class name for the <code>CryptoContextProvider</code> implementation.
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param parameters The parameters for the implementation if has.
   */
  public static void setInputCryptoContextProvider(JobConf jobConf, Class<? extends FileMatchCryptoContextProvider> cryptoContextProviderClass, 
      FileMatches fileMatches, byte[] parameters) throws CryptoException {
    byte[] secrets = fileMatches.toBytes();
    setInputCryptoContextProvider(jobConf, cryptoContextProviderClass, secrets, parameters);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for output files with {@link FileMatches}.
   * 
   * @param cryptoContextProviderClass The full class name for the <code>CryptoContextProvider</code> implementation.
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param parameters The parameters for the implementation if has.
   */
  public static void setOutputCryptoContextProvider(JobConf jobConf, Class<? extends FileMatchCryptoContextProvider> cryptoContextProviderClass,
      FileMatches fileMatches, byte[] parameters) throws CryptoException {
    byte[] secrets = fileMatches.toBytes();
    setOutputCryptoContextProvider(jobConf, cryptoContextProviderClass, secrets, parameters);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for map output files with {@link FileMatches}.
   * 
   * @param cryptoContextProviderClass The full class name for the <code>CryptoContextProvider</code> implementation.
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param parameters The parameters for the implementation if has.
   */
  public static void setMapOutputCryptoContextProvider(JobConf jobConf, Class<? extends FileMatchCryptoContextProvider> cryptoContextProviderClass,
      FileMatches fileMatches, byte[] parameters) throws CryptoException  {
    byte[] secrets = fileMatches.toBytes();
    setMapOutputCryptoContextProvider(jobConf, cryptoContextProviderClass, secrets, parameters);
  }

}
