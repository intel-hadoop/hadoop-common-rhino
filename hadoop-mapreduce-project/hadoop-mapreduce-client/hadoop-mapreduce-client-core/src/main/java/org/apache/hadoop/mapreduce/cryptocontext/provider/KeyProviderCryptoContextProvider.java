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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.io.compress.CompressionInputStream;
import org.apache.hadoop.io.compress.CompressionOutputStream;
import org.apache.hadoop.io.crypto.CryptoCodec;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.KeyProfile;
import org.apache.hadoop.io.crypto.KeyProfileResolver;
import org.apache.hadoop.io.crypto.KeyProvider;
import org.apache.hadoop.io.crypto.KeyStoreKeyProvider;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapreduce.cryptocontext.CryptoContextHelper.StageType;
import org.apache.hadoop.mapreduce.cryptocontext.provider.FileMatches.Match;
import org.apache.hadoop.util.ReflectionUtils;

/**
 * <code>KeyProviderCryptoContextProvider</code> is based on {@link FileMatchCryptoContextProvider} and
 * uses {@link KeyProvider} to provide an abstraction layer of different ways of retrieving keys 
 * from different key storages such as Java key store or third party key management systems.
 * 
 * Further more, it also provide the facilities for user to optionally encrypt the secrets and parameters
 * stored in Job Credentials which is passing through a distributed environment. 
 */

public class KeyProviderCryptoContextProvider extends FileMatchCryptoContextProvider {
  public static final String MAPRED_CLUSTER_CREDENTIAL_PROTECTION_CODEC = "mapred.cluster.credential.protection.codec";

  public static final String MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER = "mapred.cluster.encryption.key.provider";
  public static final String MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER_PARAMETERS = "mapred.cluster.encryption.key.provider.parameters";
  public static final String MAPRED_CLUSTER_ENCRYPTION_KEY_NAME = "mapred.cluster.encryption.keyname";

  public static final String MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER = "mapred.cluster.decryption.key.provider";
  public static final String MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER_PARAMETERS = "mapred.cluster.decryption.key.provider.parameters";
  public static final String MAPRED_CLUSTER_DECRYPTION_KEY_NAME = "mapred.cluster.decryption.keyname";

  private Config config;

  /**
   * Helper method for set <code>CryptoContextProvider</code> for input files with {@link FileMatches}
   * and corresponding configurations for Key Provider.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param clientSide Whether the keys are retrieved at client side before the submitting the job.
   * @param keyProviderConfig The key provider configurations
   */
  public static void setInputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, boolean clientSide, KeyProviderConfig keyProviderConfig) throws CryptoException {
    setInputCryptoContextProvider(jobConf, 
        fileMatches, clientSide, keyProviderConfig, 
        null);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for output files with {@link FileMatches}
   * and corresponding configurations for Key Provider.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param clientSide Whether the keys are retrieved at client side before the submitting the job.
   * @param keyProviderConfig The key provider configurations
   */
  public static void setOutputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, boolean clientSide, KeyProviderConfig keyProviderConfig) throws CryptoException {
    setOutputCryptoContextProvider(jobConf, 
        fileMatches, clientSide, keyProviderConfig, 
        null);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for map output files with {@link FileMatches}
   * and corresponding configurations for Key Provider.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param clientSide Whether the keys are retrieved at client side before the submitting the job.
   * @param keyProviderConfig The key provider configurations
   */
  public static void setMapOutputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, boolean clientSide, KeyProviderConfig keyProviderConfig) throws CryptoException  {
    setMapOutputCryptoContextProvider(jobConf, 
        fileMatches, clientSide, keyProviderConfig, 
        null);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for input files with {@link FileMatches},
   * corresponding configurations for Key Provider, and credential protection options.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param clientSide Whether the keys are retrieved at client side before the submitting the job.
   * @param keyProviderConfig The key provider configurations
   * @param credentialProtection The configurations for credential protection if encryption of secrets
   * and parameters is needed. If it is null, that means the no encryption is needed.
   */
  public static void setInputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, boolean clientSide, KeyProviderConfig keyProviderConfig,
      CredentialProtection credentialProtection
      ) throws CryptoException {
    setCryptoContextProvider(StageType.INPUT, jobConf, 
        fileMatches, clientSide, keyProviderConfig,
        credentialProtection);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for output files with {@link FileMatches},
   * corresponding configurations for Key Provider, and credential protection options.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param clientSide Whether the keys are retrieved at client side before the submitting the job.
   * @param keyProviderConfig The key provider configurations
   * @param credentialProtection The configurations for credential protection if encryption of secrets
   * and parameters is needed. If it is null, that means the no encryption is needed.
   */
  public static void setOutputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, boolean clientSide, KeyProviderConfig keyProviderConfig,
      CredentialProtection credentialProtection) throws CryptoException {
    setCryptoContextProvider(StageType.OUTPUT, jobConf, 
        fileMatches, clientSide, keyProviderConfig,
        credentialProtection);
  }

  /**
   * Helper method for set <code>CryptoContextProvider</code> for map output files with {@link FileMatches},
   * corresponding configurations for Key Provider, and credential protection options.
   * 
   * @param jobConf The Job configuration to store the settings.
   * @param fileMatches The file key match rules.
   * @param clientSide Whether the keys are retrieved at client side before the submitting the job.
   * @param keyProviderConfig The key provider configurations
   * @param credentialProtection The configurations for credential protection if encryption of secrets
   * and parameters is needed. If it is null, that means the no encryption is needed.
   */
  public static void setMapOutputCryptoContextProvider(JobConf jobConf, 
      FileMatches fileMatches, boolean clientSide, KeyProviderConfig keyProviderConfig,
      CredentialProtection credentialProtection) throws CryptoException  {
    setCryptoContextProvider(StageType.MAPOUTPUT, jobConf, 
        fileMatches, clientSide, keyProviderConfig,
        credentialProtection);
  }
  
  /**
   * Helper method to create the <code>KeyProviderConfig</code> object for the <code>KeyStoreKeyProvider</code>.
   */
  public static KeyProviderConfig getKeyStoreKeyProviderConfig(String keyStoreFile, String keyStoreType,
      String keyStorePassword, String keyStorePasswordFile, 
      boolean sharedPassword) throws CryptoException {
     String keyProviderParameters = KeyStoreKeyProvider.getKeyStoreParameterString(
         keyStoreFile, keyStoreType, keyStorePassword, keyStorePasswordFile, sharedPassword);
     return new KeyProviderConfig(KeyStoreKeyProvider.class.getName(), keyProviderParameters);
  }

  @Override
  public void init(byte[] parameters, byte[] secrets) throws CryptoException {
    //decrypt the parameters and secrets if needed
    Configuration conf = getConf();

    Key decryptionKey = getDecryptionKey(conf);
    if(decryptionKey != null) {
      secrets = decryptData(secrets, decryptionKey, conf);
      parameters = decryptData(parameters, decryptionKey, conf);
    }

    super.init(parameters, secrets);

    try {
      config = Config.fromBytes(parameters);
    } catch(IOException e) {
      throw new CryptoException(e);
    }
  }

  @Override
  protected Key getKey(KeyContext keyContext) throws CryptoException  {
    if(config.isClientSide()) {
      return keyContext.toKey();
    }

    //server side key retrieve
    return getKey(getConf(), config, keyContext);
  }

  @Override
  protected KeyProfile getKeyProfile(KeyContext keyContext) throws CryptoException  {
    return null;
  }

  @Override
  protected KeyProfileResolver getKeyProfileResolver(KeyContext keyContext, KeyProfile keyProfile) throws CryptoException  {
    return null;
  }

  /**
   * Wraps key provider configurations. 
   */
  public static class KeyProviderConfig implements Writable {
    private String keyProvider;
    private String keyProviderParameters; 

    /**
     * A new key provider configuration object.
     */
    public KeyProviderConfig() {
    }

    /**
     * A new key provider configuration object with specified attributes.
     */
    public KeyProviderConfig(String keyProvider, String keyProviderParameters) {
      super();
      this.keyProvider = keyProvider;
      this.keyProviderParameters = keyProviderParameters;
    }

    /**
     * Returns the key provider full class name.
     */
    public String getKeyProvider() {
      return keyProvider;
    }

    /**
     * Returns the key provider parameters.
     */
    public String getKeyProviderParameters() {
      return keyProviderParameters;
    }

    /**
     * Validate the configuration object.
     */
    public void validate() throws CryptoException {
      if(keyProvider == null ||
          keyProvider.isEmpty())
        throw new CryptoException("Key provider is not specified.");
    }

    @Override
    public void write(DataOutput out) throws IOException {
      Text.writeString(out, keyProvider);

      if(keyProviderParameters != null) {
        out.writeBoolean(true);
        Text.writeString(out, keyProviderParameters);
      } else {
        out.writeBoolean(false);
      }
    }

    @Override
    public void readFields(DataInput in) throws IOException {
      keyProvider = Text.readString(in);

      boolean hasParameters = in.readBoolean();
      if(hasParameters)
        keyProviderParameters = Text.readString(in);
      else
        keyProviderParameters = null;
    }

    public byte[] toBytes() throws IOException {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(outputStream);

      write(out);
      return outputStream.toByteArray();
    }

    public static KeyProviderConfig fromBytes(byte[] bytes) throws IOException {
      if(bytes == null || 
          bytes.length <= 0)
        return null;

      ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
      DataInputStream in = new DataInputStream(inputStream);

      KeyProviderConfig config = new KeyProviderConfig();
      config.readFields(in);
      return config;
    }
  }

  /**
   * <code>CredentialProtection</code> wraps the credential protection configurations.
   * Generally, an asymmetric algorithm should be used such as RSA or PGP.
   */
  public static class CredentialProtection {
    private Class<? extends CryptoCodec> credentialCryptoCodecClass;

    private KeyProviderConfig encryptionKeyProviderConfig;
    private String encryptionKeyName;

    private KeyProviderConfig decryptionKeyProviderConfig;
    private String decryptionKeyName;

    public CredentialProtection(Configuration conf) {
      this.credentialCryptoCodecClass = conf.getClass(MAPRED_CLUSTER_CREDENTIAL_PROTECTION_CODEC, 
          null, CryptoCodec.class);

      if(credentialCryptoCodecClass != null) {
        String encryptionKeyProviderClass = conf.get(MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER, null);
        if(encryptionKeyProviderClass != null) {
          String encryptionKeyProviderParameters = conf.get(MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER_PARAMETERS, "");
          this.encryptionKeyProviderConfig = new KeyProviderConfig(
              encryptionKeyProviderClass, encryptionKeyProviderParameters);
          
          this.encryptionKeyName = conf.get(MAPRED_CLUSTER_ENCRYPTION_KEY_NAME, null);
        }
        
        String decryptionKeyProviderClass = conf.get(MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER, null);
        if(decryptionKeyProviderClass != null) {
          String decryptionKeyProviderParameters = conf.get(MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER_PARAMETERS, "");
          this.decryptionKeyProviderConfig = new KeyProviderConfig(
              decryptionKeyProviderClass, decryptionKeyProviderParameters);
          this.decryptionKeyName = conf.get(MAPRED_CLUSTER_DECRYPTION_KEY_NAME, null);
        }
      }
    }
    
    /**
     * A new credential protection configuration object with specified attributes.
     * 
     * @param conf The configuration to initialize the default
     * @param credentialCryptoCodecClass The <code>CryptoCodec</code> class to be used for encrypting and decrypting.
     * @param encryptionKeyProviderConfig The key provider configuration for retrieving encryption key.
     * @param encryptionKeyName The encryption key name
     * @param decryptionKeyProviderConfig The key provider configuration for retrieving decryption key.
     * @param decryptionKeyName The decryption key name
     */
    public CredentialProtection(Configuration conf,
        Class<? extends CryptoCodec> credentialCryptoCodecClass,
        KeyProviderConfig encryptionKeyProviderConfig,String encryptionKeyName,
        KeyProviderConfig decryptionKeyProviderConfig, String decryptionKeyName) {
      this(conf);
      
      if(credentialCryptoCodecClass != null)
        this.credentialCryptoCodecClass = credentialCryptoCodecClass;
      
      if(encryptionKeyProviderConfig != null)
        this.encryptionKeyProviderConfig = encryptionKeyProviderConfig;
      
      if(encryptionKeyName != null)
        this.encryptionKeyName = encryptionKeyName;
      
      if(decryptionKeyProviderConfig != null)
        this.decryptionKeyProviderConfig = decryptionKeyProviderConfig;
      
      if(decryptionKeyName != null)
        this.decryptionKeyName = decryptionKeyName;
    }
    
    /**
     * Check whether the credential protection is configured or not
     */
    public boolean isEmpty() {
      if(credentialCryptoCodecClass == null)
        return true;
      
      return false;
    }

    /**
     * Validate the configuration object.
     */
    public void validate() throws CryptoException {
      if((encryptionKeyProviderConfig != null ||
          decryptionKeyProviderConfig != null) &&
          credentialCryptoCodecClass == null
          )
        throw new CryptoException(
            "Credential crypto codec is not specified.");

      if(encryptionKeyProviderConfig != null) {
        if(decryptionKeyProviderConfig == null)
          throw new CryptoException(
              "Credential encryption is configured but decryption is not configured.");

        encryptionKeyProviderConfig.validate();
        decryptionKeyProviderConfig.validate();

        if(encryptionKeyName == null ||
            encryptionKeyName.isEmpty())
          throw new CryptoException(
              "Credential encryption key is not specified.");

        if(decryptionKeyName == null ||
            decryptionKeyName.isEmpty())
          throw new CryptoException(
              "Credential decryption key is not specified.");
      } else {
        if(decryptionKeyProviderConfig != null)
          throw new CryptoException(
              "Credential decryption is configured but encryption is not configured.");
      }
    }

    /**
     * Returns the key provider configuration for retrieving encryption key.
     */
    public KeyProviderConfig getEncryptionKeyProviderConfig() {
      return encryptionKeyProviderConfig;
    }

    /**
     * Returns the encryption key name.
     */
    public String getEncryptionKeyName() {
      return encryptionKeyName;
    }

    /**
     * Returns the key provider configuration for retrieving decryption key.
     */
    public KeyProviderConfig getDecryptionKeyProviderConfig() {
      return decryptionKeyProviderConfig;
    }

    /**
     * Returns the decrytion key name.
     */
    public String getDecryptionKeyName() {
      return decryptionKeyName;
    }

    /**
     * Set the configurations key values related to credential protection to Job Configuration.
     */
    public void setConf(Configuration conf) {
      if(credentialCryptoCodecClass == null)
        return;

      conf.setClass(MAPRED_CLUSTER_CREDENTIAL_PROTECTION_CODEC,
          credentialCryptoCodecClass, RSACredentialProtectionCodec.class);

      //encryption
      conf.set(MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER, 
          encryptionKeyProviderConfig.getKeyProvider());

      String encryptionParameters = 
          encryptionKeyProviderConfig.getKeyProviderParameters();
      if(encryptionParameters != null &&
          !encryptionParameters.isEmpty()) {
        conf.set(MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER_PARAMETERS, encryptionParameters);
      }

      conf.set(MAPRED_CLUSTER_ENCRYPTION_KEY_NAME, encryptionKeyName);

      //decryption
      conf.set(MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER, 
          decryptionKeyProviderConfig.getKeyProvider());

      String decryptionParameters = 
          decryptionKeyProviderConfig.getKeyProviderParameters();
      if(decryptionParameters != null &&
          !decryptionParameters.isEmpty()) {
        conf.set(MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER_PARAMETERS, decryptionParameters);
      }

      conf.set(MAPRED_CLUSTER_DECRYPTION_KEY_NAME, decryptionKeyName);
    }
  }

  /**
   * A data wrapper class which wraps the <code>KeyproviderCryptoContextProvider</code> parameters.
   */
  static class Config implements Writable {
    private boolean clientSide = true;
    private KeyProviderConfig keyProviderConfig;

    /**
     * A new object.
     */
    public Config() {
    }

    /**
     * A new object with specified attributes.
     */
    public Config(boolean clientSide, KeyProviderConfig keyProviderConfig) {
      super();
      this.clientSide = clientSide;
      this.keyProviderConfig = keyProviderConfig;
    }

    public boolean isClientSide() {
      return clientSide;
    }

    public KeyProviderConfig getKeyProviderConfig() {
      return keyProviderConfig;
    }

    @Override
    public void write(DataOutput out) throws IOException {
      out.writeBoolean(clientSide);
      if(!clientSide) {
        keyProviderConfig.write(out);
      }
    }

    @Override
    public void readFields(DataInput in) throws IOException {
      clientSide = in.readBoolean();
      if(!clientSide) {
        keyProviderConfig = new KeyProviderConfig();
        keyProviderConfig.readFields(in);
      }
    }

    public byte[] toBytes() throws IOException {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(outputStream);

      write(out);
      return outputStream.toByteArray();
    }

    public static Config fromBytes(byte[] bytes) throws IOException {
      if(bytes == null || 
          bytes.length <= 0)
        return null;

      ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
      DataInputStream in = new DataInputStream(inputStream);

      Config config = new Config();
      config.readFields(in);
      return config;
    }
  }

  protected static Key getKey(Configuration conf, Config config, KeyContext keyContext) throws CryptoException  {
    KeyProvider keyProvider = getKeyProvider(conf, config);
    return getKey(keyProvider, conf, config, keyContext);
  }

  protected static Key getKey(KeyProvider keyProvider, Configuration conf, Config config, KeyContext keyContext) throws CryptoException  {
    String keyName = keyContext.toReference();
    String[] keyNames = new String[] {keyName};

    Key[] keys = keyProvider.getKeys(keyNames);
    Key key = keys[0];

    //check the key data
    if(key.getKeyType() != keyContext.getKeyType())
      throw new CryptoException("The key type of the Key from the Key Provider is not the same with the Key Context.");

    if(key.getCryptographicAlgorithm() == null)
      key.setCryptographicAlgorithm(keyContext.getCryptographicAlgorithm());

    if(key.getCryptographicLength() == 0)
      key.setCryptographicLength(keyContext.getCryptographicLength());

    return key;
  }

  protected static void setCryptoContextProvider(StageType stageType, JobConf jobConf, 
      FileMatches fileMatches, boolean clientSide, KeyProviderConfig keyProviderConfig,
      CredentialProtection credentialProtection) throws CryptoException {
    if(keyProviderConfig == null)
      throw new CryptoException("Key provider config is not specified.");

    keyProviderConfig.validate();

    if(credentialProtection != null) {
      credentialProtection.validate();
      credentialProtection.setConf(jobConf);
    } else {
      // Check the system default
      credentialProtection = new CredentialProtection(jobConf);
      if(!credentialProtection.isEmpty()) {
        credentialProtection.validate();
        credentialProtection.setConf(jobConf);
      }
    }

    Config config = new Config(clientSide, keyProviderConfig);
    byte[] parameters = null;

    try {
      parameters = config.toBytes();
    } catch(IOException e) {
      throw new CryptoException(e);
    }

    if(clientSide) {
      //client side populate the keys as the key store file is at client side
      fileMatches = convertKeyContext(jobConf, config, fileMatches);
    }

    byte[] secrets = fileMatches.toBytes();

    //encrypt the secretes and parameters if needed
    Key encryptionKey = getEncryptionKey(jobConf);
    if(encryptionKey != null) {
      secrets = encryptData(secrets, encryptionKey, jobConf);
      parameters = encryptData(parameters, encryptionKey, jobConf);
    }

    switch(stageType) {
    case INPUT: {
      setInputCryptoContextProvider(jobConf, KeyProviderCryptoContextProvider.class, secrets, parameters);
      break;
    }
    case OUTPUT: {
      setOutputCryptoContextProvider(jobConf, KeyProviderCryptoContextProvider.class, secrets, parameters);
      break;
    }
    case MAPOUTPUT: {
      setInputCryptoContextProvider(jobConf, KeyProviderCryptoContextProvider.class, secrets, parameters);
      break;
    }
    }
  }

  protected static FileMatches convertKeyContext(JobConf jobConf, Config config, FileMatches fileMatches) throws CryptoException {
    KeyProvider keyProvider = getKeyProvider(jobConf, config);

    KeyContext defaultKeyContext = fileMatches.getDefaultKeyContext();
    if(defaultKeyContext != null) {
      defaultKeyContext = convertKeyContext(keyProvider, jobConf, config, defaultKeyContext);
    }

    FileMatches newFileMatches = new FileMatches(defaultKeyContext);

    List<Match> matches = fileMatches.getMatches();
    for(Match match : matches) {
      KeyContext newKeyContext = convertKeyContext(keyProvider, jobConf, config, match.getKeyContext());
      Match newMatch = new Match(match.getRegex(), newKeyContext, match.isMatchName());
      newFileMatches.addMatch(newMatch);
    }

    return newFileMatches;
  }

  protected static KeyContext convertKeyContext(KeyProvider keyProvider, JobConf jobConf, Config config, KeyContext keyContext) throws CryptoException {
    Key key = getKey(keyProvider, jobConf, config, keyContext);
    return KeyContext.fromKey(key);
  }

  protected static KeyProvider getKeyProvider(Configuration conf, Config config) throws CryptoException {
    KeyProviderConfig keyProviderConfig = config.getKeyProviderConfig();
    if(keyProviderConfig == null)
      throw new CryptoException("No key provider configuration is specified.");

    String keyProviderClassName = keyProviderConfig.getKeyProvider();
    if(keyProviderClassName == null ||
        keyProviderClassName.isEmpty()) {
      throw new CryptoException("No key provider is specified.");
    }

    return getKeyProvider(conf, keyProviderClassName, keyProviderConfig.getKeyProviderParameters());
  }

  protected static KeyProvider getEncryptionKeyProvider(Configuration conf) throws CryptoException {
    return getClusterKeyProvider(conf,
        MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER, 
        MAPRED_CLUSTER_ENCRYPTION_KEY_PROVIER_PARAMETERS);
  }

  protected static KeyProvider getDecryptionKeyProvider(Configuration conf) throws CryptoException {
    return getClusterKeyProvider(conf,
        MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER, 
        MAPRED_CLUSTER_DECRYPTION_KEY_PROVIER_PARAMETERS);
  }

  protected static KeyProvider getClusterKeyProvider(Configuration conf, 
      String keyProviderKey, String keyProviderParametersKey) throws CryptoException {
    String keyProviderClassName = conf.get(keyProviderKey);

    String keyProviderParameters = conf.get(keyProviderParametersKey);
    return getKeyProvider(conf, keyProviderClassName, keyProviderParameters);
  }

  protected static KeyProvider getKeyProvider(Configuration conf,
      String keyProviderClassName, String keyProviderParameters) throws CryptoException {
    if(keyProviderClassName == null ||
        keyProviderClassName.isEmpty())
      return null;

    Class<?> keyProviderClass = 
        getClass(conf, keyProviderClassName, null, KeyProvider.class);

    if(keyProviderClass == null)
      throw new CryptoException("Key provider class cannot be found.");

    KeyProvider keyProvider = 
        (KeyProvider) ReflectionUtils.newInstance(keyProviderClass, conf);

    if(keyProvider == null)
      throw new CryptoException("Failed to instance key provider: " + keyProviderClassName);

    keyProvider.init(keyProviderParameters);
    return keyProvider;
  }

  protected static <U> Class<? extends U> getClass(Configuration conf, String className, 
      Class<? extends U> defaultValue, 
      Class<U> xface) throws CryptoException {
    try {
      Class<?> theClass = conf.getClassByName(className);
      if (theClass != null && !xface.isAssignableFrom(theClass))
        throw new CryptoException(theClass+" not "+xface.getName());
      else if (theClass != null)
        return theClass.asSubclass(xface);
      else
        return defaultValue;
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  protected static Key getEncryptionKey(Configuration conf) throws CryptoException {
    KeyProvider keyProvider = getEncryptionKeyProvider(conf);
    if(keyProvider == null)
      return null;

    String keyName = conf.get(MAPRED_CLUSTER_ENCRYPTION_KEY_NAME);
    if(keyName == null ||
        keyName.isEmpty())
      return null;

    return getKey(conf, keyProvider, keyName);
  }

  protected static Key getDecryptionKey(Configuration conf) throws CryptoException {
    KeyProvider keyProvider = getDecryptionKeyProvider(conf);
    if(keyProvider == null)
      return null;

    String keyName = conf.get(MAPRED_CLUSTER_DECRYPTION_KEY_NAME);
    if(keyName == null ||
        keyName.isEmpty())
      return null;

    return getKey(conf, keyProvider, keyName);
  }

  protected static Key getKey(Configuration conf, KeyProvider keyProvider, String keyName) throws CryptoException {
    String[] keyNames = new String[]{keyName};
    Key[] keys = keyProvider.getKeys(keyNames);
    return keys[0];
  }

  protected static byte[] encryptData(byte[] data, Key key, Configuration conf) throws CryptoException {
    CryptoCodec codec = getCredentialProtectionCodec(conf);

    CryptoContext cryptoContext = new CryptoContext();
    cryptoContext.setKey(key);
    codec.setCryptoContext(cryptoContext);

    ByteArrayOutputStream os = new ByteArrayOutputStream();
    try {
      CompressionOutputStream out = codec.createOutputStream(os);

      try {
        out.write(data);
        out.flush();
      } finally {
        out.close();
      }
    } catch(IOException e) {
      throw new CryptoException(e);
    }

    return os.toByteArray();
  }

  protected static byte[] decryptData( byte[] data, Key key, Configuration conf) throws CryptoException {
    CryptoCodec codec = getCredentialProtectionCodec(conf);

    CryptoContext cryptoContext = new CryptoContext();
    cryptoContext.setKey(key);
    codec.setCryptoContext(cryptoContext);

    ByteArrayInputStream is = new ByteArrayInputStream(data);

    try {
      CompressionInputStream in = codec.createInputStream(is);

      try {
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        byte[] buffer = new byte[1024];
        int r;
        while ( (r = in.read(buffer)) > -1) {
          //write
          os.write(buffer, 0, r);
        }

        return os.toByteArray();
      } finally {
        in.close();
      }
    } catch(IOException e) {
      throw new CryptoException(e);
    }
  }

  protected static CryptoCodec getCredentialProtectionCodec(Configuration conf) throws CryptoException {
    String className = conf.get(MAPRED_CLUSTER_CREDENTIAL_PROTECTION_CODEC);
    if(className == null)
      throw new CryptoException("Credential protection codec is not specified.");

    Class<?>  credentialProtectionCodecClass = 
        getClass(conf, className, null, CryptoCodec.class);

    if(credentialProtectionCodecClass == null)
      throw new CryptoException("Credential protection codec class cannot be found.");

    CryptoCodec credentialProtectionCodec = 
        (CryptoCodec) ReflectionUtils.newInstance(credentialProtectionCodecClass, conf);

    if(credentialProtectionCodec == null)
      throw new CryptoException("Failed to instance crypto codec: " + credentialProtectionCodecClass);

    return credentialProtectionCodec;
  }
}
