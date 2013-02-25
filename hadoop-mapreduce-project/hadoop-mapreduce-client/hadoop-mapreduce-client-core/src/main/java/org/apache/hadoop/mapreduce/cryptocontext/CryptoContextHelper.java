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

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.crypto.CryptoCodec;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapreduce.cryptocontext.CryptoContextProvider.Purpose;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.util.ReflectionUtils;

/**
 * The helper class which defines the configuration keys that used for MapReduce job which support
 * encryption and decrytpion, and the helper methods to retrieving {@link CryptoContext} using the
 * crypto context provider mechanism and to be used in the MapReduce core process to minimize
 * modification in the core process.
 *
 */
public final class CryptoContextHelper {
  private static final Log LOG = LogFactory.getLog(CryptoContextHelper.class);

  public static final String MAPRED_INPUT_CRYPTO_CONTEXT_PROVIER = "mapred.input.crypto.context.provider";
  public static final String MAPRED_OUTPUT_CRYPTO_CONTEXT_PROVIER = "mapred.output.crypto.context.provider";
  public static final String MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_PROVIER = "mapred.map.output.crypto.context.provider";

  public static final String MAPRED_INPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS = "mapred.input.crypto.context.provider.parameters";
  public static final String MAPRED_OUTPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS = "mapred.output.crypto.context.provider.parameters";
  public static final String MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS = "mapred.map.output.crypto.context.provider.parameters";

  public static final String MAPRED_INPUT_CRYPTO_CONTEXT_SECRETS = "mapred.input.crypto.context.secrets";
  public static final String MAPRED_OUTPUT_CRYPTO_CONTEXT_SECRETS = "mapred.output.crypto.context.secrets";
  public static final String MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_SECRETS = "mapred.map.output.crypto.context.secrets";

  /**
   * Stage type enumeration that defines different stages of MapReduce job.
   *
   */
  public static enum StageType {
    INPUT,
    OUTPUT,
    MAPOUTPUT;
  }

  /**
   * Return the {@link CryptoContext} for a input file according to the file path.
   * @param job The job configuration
   * @param file The file path of the file.
   * @return The <code>CryptoContext</code> for using for the file.
   */
  public static CryptoContext getInputCryptoContext(JobConf job, Path file) throws IOException {
    try {
      return getCryptoContext(job, 
          MAPRED_INPUT_CRYPTO_CONTEXT_PROVIER,
          MAPRED_INPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS,
          MAPRED_INPUT_CRYPTO_CONTEXT_SECRETS,
          file,
          Purpose.DECRYPTION,
          StageType.INPUT);
    } catch(CryptoException e) {
      throw new IOException(e);
    }
  }

  /**
   * Set the {@link CryptoContext} to {@link CryptoCodec} for a input file.
   * 
   * @param cryptoCodec The <code>CryptoCodec</code> object to set context for.
   * @param job The job configuration
   * @param file The file path of the file.
   */
  public static void resetInputCryptoContext(CryptoCodec cryptoCodec, JobConf job, Path file) throws IOException {
    CryptoContext cryptoContext = getInputCryptoContext(job, file);
    setCryptoContext(cryptoCodec, cryptoContext, file);
  }

  /**
   * Return the {@link CryptoContext} for a output file according to the file path.
   * @param job The job configuration
   * @param file The file path of the file.
   * @return The <code>CryptoContext</code> for using for the file.
   */
  public static CryptoContext getOutputCryptoContext(JobConf job, Path file) throws IOException {
    try {
      return getCryptoContext(job,
          MAPRED_OUTPUT_CRYPTO_CONTEXT_PROVIER,
          MAPRED_OUTPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS,
          MAPRED_OUTPUT_CRYPTO_CONTEXT_SECRETS,
          file,
          Purpose.ENCRYPTION,
          StageType.OUTPUT);
    } catch(CryptoException e) {
      throw new IOException(e);
    }
  }

  /**
   * Set the {@link CryptoContext} to {@link CryptoCodec} for a output file.
   * 
   * @param cryptoCodec The <code>CryptoCodec</code> object to set context for.
   * @param job The job configuration
   * @param file The file path of the file.
   */
  public static void resetOutputCryptoContext(CryptoCodec cryptoCodec, JobConf job, Path file) throws IOException {
    CryptoContext cryptoContext = getOutputCryptoContext(job, file);
    setCryptoContext(cryptoCodec, cryptoContext, file);
  }

  /**
   * Return the {@link CryptoContext} for a map output or map input file according to the file path.
   * @param job The job configuration
   * @param file The file path of the file
   * @param purpose The purpose identifies map output or map input
   * @return The <code>CryptoContext</code> for using for the file.
   */
  public static CryptoContext getMapOutputCryptoContext(JobConf job, Path file, Purpose purpose) {
    try {
      return getCryptoContext(job, 
          MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_PROVIER,
          MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_PROVIER_PARAMETERS,
          MAPRED_MAP_OUTPUT_CRYPTO_CONTEXT_SECRETS,
          file,
          purpose,
          StageType.MAPOUTPUT);
    } catch(CryptoException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Set the {@link CryptoContext} to {@link CryptoCodec} for a map output file.
   * 
   * @param cryptoCodec The <code>CryptoCodec</code> object to set context for.
   * @param job The job configuration
   * @param file The file path of the file.
   */
  public static void resetMapOutputCryptoContext(CryptoCodec cryptoCodec, JobConf job, Path file) {
    CryptoContext cryptoContext = getMapOutputCryptoContext(job, file, Purpose.ENCRYPTION);
    setCryptoContext(cryptoCodec, cryptoContext, file);
  }

  /**
   * Set the {@link CryptoContext} to {@link CryptoCodec} for a map input file.
   * 
   * @param cryptoCodec The <code>CryptoCodec</code> object to set context for.
   * @param job The job configuration
   * @param file The file path of the file.
   */
  public static void resetReduceInputCryptoContext(CryptoCodec cryptoCodec, JobConf job, Path file) {
    CryptoContext cryptoContext = getMapOutputCryptoContext(job, file, Purpose.DECRYPTION);
    setCryptoContext(cryptoCodec, cryptoContext, file);
  }

  /**
   * Return the {@link CryptoContext} according the parameters specified.
   */
  public static CryptoContext getCryptoContext(JobConf job, String providerKey, 
      String parametersKey, String secretsKey, 
      Path file, Purpose purpose, StageType stage) throws CryptoException {
    //get the key by file
    Class<? extends CryptoContextProvider> cryptoContextProviderClass = 
        job.getClass(providerKey, null, CryptoContextProvider.class);

    if(cryptoContextProviderClass == null)
      return null;

    byte[] parameters = null;
    byte[] secrets = null;

    Credentials credentials = job.getCredentials();
    if(credentials != null) {
      parameters = credentials.getSecretKey(new Text(parametersKey));
      secrets = credentials.getSecretKey(new Text(secretsKey));
    }

    CryptoContextProvider cryptoContextProvider = 
        (CryptoContextProvider) ReflectionUtils.newInstance(cryptoContextProviderClass, job);

    cryptoContextProvider.init(parameters, secrets);

    CryptoContext cryptoContext = cryptoContextProvider.getCryptoContext(file, purpose);

    if(cryptoContext == null) {
      LOG.warn("No " + purpose + " crypto context was provided from provider " + cryptoContextProviderClass.getName() + 
          " for " + stage + " file: " + file);
    } else {
      LOG.info("Get " + purpose + " crypto context for " + stage + " file: " + file + ", context: " + cryptoContext.toString());
    }

    return cryptoContext;
  }

  private static void setCryptoContext(CryptoCodec cryptoCodec, CryptoContext cryptoContext, Path file) {
    cryptoCodec.setCryptoContext(cryptoContext);
  }
}
