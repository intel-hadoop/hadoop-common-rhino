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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.KeyProfile;
import org.apache.hadoop.io.crypto.KeyProfileResolver;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapreduce.cryptocontext.CryptoContextHelper;
import org.apache.hadoop.mapreduce.cryptocontext.CryptoContextProvider;
import org.apache.hadoop.security.Credentials;

/**
 * <code>AbstractCryptoContextProvider</code> is an abstract base class for providing some
 * common implementations that can be shared with different <code>CryptoContextProvider</code> 
 * implementations.
 */

public abstract class AbstractCryptoContextProvider implements CryptoContextProvider {
  private Configuration conf;

  @Override
  public void setConf(Configuration conf) {
    this.conf = conf;
  }

  @Override
  public Configuration getConf() {
    return conf;
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for input files and related parameters and secrets.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param cryptoContextProviderClass The full class name for the <code>CryptoContextProvider</code> implementation.
   * @param secrets The secrets for the implementation.
   * @param parameters The parameters for the implementation.
   */
  public static void setInputCryptoContextProvider(JobConf jobConf, 
      Class<? extends AbstractCryptoContextProvider> cryptoContextProviderClass, byte[] secrets, byte[] parameters) {
    setCryptoContextProvider(jobConf, cryptoContextProviderClass, secrets, parameters,
        CryptoContextHelper.MAPRED_INPUT_CRYPTO_CONTEXT_PROVIER,
        CryptoContextHelper.MAPRED_INPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS,
        CryptoContextHelper.MAPRED_INPUT_CRYPTO_CONTEXT_SECRETS);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for output files and related parameters and secrets.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param cryptoContextProviderClass The full class name for the <code>CryptoContextProvider</code> implementation.
   * @param secrets The secrets for the implementation.
   * @param parameters The parameters for the implementation.
   */
  public static void setOutputCryptoContextProvider(JobConf jobConf, 
      Class<? extends AbstractCryptoContextProvider> cryptoContextProviderClass, byte[] secrets, byte[] parameters) {
    setCryptoContextProvider(jobConf, cryptoContextProviderClass, secrets, parameters,
        CryptoContextHelper.MAPRED_OUTPUT_CRYPTO_CONTEXT_PROVIER,
        CryptoContextHelper.MAPRED_OUTPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS,
        CryptoContextHelper.MAPRED_OUTPUT_CRYPTO_CONTEXT_SECRETS);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for map output files and related parameters and secrets.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param cryptoContextProviderClass The full class name for the <code>CryptoContextProvider</code> implementation.
   * @param secrets The secrets for the implementation.
   * @param parameters The parameters for the implementation.
   */
  public static void setMapOutputCryptoContextProvider(JobConf jobConf,
      Class<? extends AbstractCryptoContextProvider> cryptoContextProviderClass, byte[] secrets, byte[] parameters) {
    setCryptoContextProvider(jobConf, cryptoContextProviderClass, secrets, parameters,
        CryptoContextHelper.MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_PROVIER,
        CryptoContextHelper.MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS,
        CryptoContextHelper.MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_SECRETS);
  }

  protected static void setCryptoContextProvider(JobConf jobConf,
      Class<? extends AbstractCryptoContextProvider> cryptoContextProviderClass, byte[] secrets, byte[] parameters,
      String providerKey, String parametersKey, String secretsKey) {
    jobConf.setClass(providerKey,
        cryptoContextProviderClass, CryptoContextProvider.class);

    if(parameters == null)
      parameters = new byte[0];

    if(secrets == null)
      secrets = new byte[0];

    Credentials credentials = jobConf.getCredentials();
    credentials.addSecretKey(new Text(parametersKey), parameters);
    credentials.addSecretKey(new Text(secretsKey), secrets);  

  }


  /**
   * The default implementation of <code>getCryptoContext</code> with {@link KeyContext}
   * The inherited implementation will implement <code>getKeyContext</code> which returns
   * the <code>KeyContext</code>, then <code>getKeyProfile</code> for returning a {@link KeyProfile}
   * from the <code>KeyContext</code> if has, and <code>getKeyProfileResolver</code> for returning the
   * {@link KeyProfileResolver} if has.
   */
  @Override
  public CryptoContext getCryptoContext(Object context, Purpose purpose) throws CryptoException {
    KeyContext keyContext = getKeyContext(context, purpose);
    if(keyContext == null)
      return null;

    Key key = getKey(keyContext);
    KeyProfile keyProfile = getKeyProfile(keyContext);
    KeyProfileResolver keyProfileResolver = getKeyProfileResolver(keyContext, keyProfile);

    return new CryptoContext(key, keyProfile, keyProfileResolver);
  }

  /**
   * Returns the {@link KeyContext} from the file context and purpose.
   */
  abstract protected KeyContext getKeyContext(Object context, Purpose purpose) throws CryptoException  ;

  /**
   * Map a Key Context for a Key if possible
   * 
   * By default mapKey assumes the KyeContext stores the raw key context
   * Users can override the map key to to retrieve the real key if the 
   * KeyInfo doesn't store the key reference such as a key id.
   */
  abstract protected Key getKey(KeyContext keyContext) throws CryptoException ;

  /**
   * Get a Key Profile for Key Context, return null if there is no Key Profile for a specific context
   * The Key Profile are the information stored with the encrypted data for key association
   */
  protected KeyProfile getKeyProfile(KeyContext keyContext) throws CryptoException  {
    return null;
  }

  /**
   * Get a Key Profile Resolver from the Key Context and Key Profile
   * The Key Profile are the information stored with the encrypted data for key association
   */
  protected KeyProfileResolver getKeyProfileResolver(KeyContext keyContext, KeyProfile keyProfile) throws CryptoException  {
    return null;
  }
}
