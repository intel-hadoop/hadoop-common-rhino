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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.SecretKey;

import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;

/**
 * <code>KeyStoreKeyProvider</code> provides a {@link KeyProvider} implementation to provide
 * the ability to retrieve keys from a "JCEKS" key store.
 */

public class KeyStoreKeyProvider implements KeyProvider {
  public static final String PASSWORD_PROPERTY_SUFFIX = ".password";
  public static final String KEY_STORE_PASSWORD_PROPERTY = "keystore" + PASSWORD_PROPERTY_SUFFIX;
  public static final String DEFAULT_KEY_STORE_TYPE = "JKS";
  
  private Configuration conf;
  private KeyStoreConfig keyStoreConfig;
  
  private KeyStore keyStore;
  private Properties passwords;
  
  /**
   * Helper method to get parameter string for the <code>KeyStoreKeyProvider</code>.
   * The parameter string is in the format of URL query string with UTF8 encoding. 
   * For example, keyStoreUrl=abc.store&keyStoreType=JKS&passwordFile=passwords.properties
   */
  public static String getKeyStoreParameterString(String keyStoreFile, String keyStoreType,
      String keyStorePassword, String keyStorePasswordFile, 
      boolean sharedPassword) throws CryptoException {
    
    KeyStoreConfig keyStoreConfig = new KeyStoreConfig(keyStoreFile, keyStoreType, 
        keyStorePassword, keyStorePasswordFile, sharedPassword);
    
     return keyStoreConfig.toParameterString();
     
  }
  
  /**
   * Helper method to get parameter string use the default encryption algorithm
   * defined by <code>DEFAULT_KEY_STORE_TYPE</code> for the <code>KeyStoreKeyProvider</code>
   */
  public static String getKeyStoreParameterString(String keyStoreFile,
      String keyStorePassword, String keyStorePasswordFile, boolean sharedPassword) throws CryptoException {
      return getKeyStoreParameterString(keyStoreFile, DEFAULT_KEY_STORE_TYPE, 
          keyStorePassword, keyStorePasswordFile, sharedPassword);
  }
  
  /**
   * Parses an URL query string and returns a map with the parameter values.
   * The URL query string is the part in the URL after the first '?' character up
   * to an optional '#' character. It has the format "name=value&name=value&...".
   * The map has the same structure as the one returned by
   * javax.servlet.ServletRequest.getParameterMap().
   * A parameter name may occur multiple times within the query string.
   * For each parameter name, the map contains a string array with the parameter values.
   * @param  s  an URL query string.
   * @return a map containing parameter names as keys and parameter values as map values.
   */
  public static Map<String, String[]> parseUrlQueryString (String s) {
    if (s == null) {
      return new HashMap<String, String[]>(0);
    }

    // In map1 we use strings and ArrayLists to collect the parameter values.
    HashMap<String, Object> map1 = new HashMap<String, Object>();
    int p = 0;
    while (p < s.length()) {
      int p0 = p;
      while (p < s.length() && s.charAt(p) != '=' && s.charAt(p) != '&') 
        p++;
      String name = urlDecode(s.substring(p0, p));
      if (p < s.length() && s.charAt(p) == '=') 
        p++;
      p0 = p;
      while (p < s.length() && s.charAt(p) != '&') 
        p++;
      String value = urlDecode(s.substring(p0, p));
      if (p < s.length() && s.charAt(p) == '&') 
        p++;

      Object x = map1.get(name);
      if (x == null) {
        // The first value of each name is added directly as a string to the map.
        map1.put (name, value); 
      } else if (x instanceof String) {
        // For multiple values, we use an ArrayList.
        ArrayList<String> a = new ArrayList<String>();
        a.add ((String)x);
        a.add (value);
        map1.put (name, a); 
      } else {
        @SuppressWarnings("unchecked")
        ArrayList<String> a = (ArrayList<String>)x;
        a.add (value); 
      }
    }

    // Copy map1 to map2. Map2 uses string arrays to store the parameter values.
    HashMap<String, String[]> map2 = new HashMap<String, String[]>(map1.size());
    for (Map.Entry<String, Object> e : map1.entrySet()) {
      String name = e.getKey();
      Object x = e.getValue();
      String[] v;
      if (x instanceof String) {
        v = new String[]{(String)x}; 
      } else {
        @SuppressWarnings("unchecked")
        ArrayList<String> a = (ArrayList<String>)x;
        v = new String[a.size()];
        v = a.toArray(v); 
      }
      map2.put (name, v); 
    }
    return map2; 
  }
  
  public static String toUrlQueryString(Map<String, List<String>> parameterMap) {
    StringBuilder sb = new StringBuilder();

    for (Map.Entry<String,List<String>> entry : parameterMap.entrySet()) {
      List<String> values = entry.getValue();
      for(String value : values) {
        if (sb.length() > 0) {
          sb.append("&");
        }

        //name
        sb.append(urlEncode(entry.getKey()));
        sb.append('=');
        sb.append(urlEncode(value));
      }
    }
    
    return sb.toString();
  }
  
  /**
   * Help method to get a single parameter value from parameter map
   */
  public static String getParameter(Map<String, String[]> parameterMap, 
      String name, String defaultValue) {
    String[] values = parameterMap.get(name);
    if(values == null || 
        values.length <= 0) {
      return defaultValue;
    }
    
    return values[0];
  }
  
  /**
   * Help method to add a single parameter value to parameter map
   */
  public static void addParameter(Map<String, List<String>> parameterMap, 
      String name, String value) {
    if(value == null)
      return;
    
    List<String> values = parameterMap.get(name);
    if(values == null) {
      values = new ArrayList<String>();
      values.add(value);
      parameterMap.put(name, values);
    } else {
      values.add(value);
    }    
  }

  private static String urlDecode (String s) {
    try {
      return URLDecoder.decode(s, "UTF-8"); 
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException("Error in urlDecode.", e); 
    }
  }
  
  private static String urlEncode(String s) {
    try {
        return URLEncoder.encode(s, "UTF-8");
    } catch (UnsupportedEncodingException e) {
        throw new UnsupportedOperationException(e);
    }
}
  
  @Override
  public void setConf(Configuration conf) {
    this.conf = conf;
  }

  @Override
  public Configuration getConf() {
    return conf;
  }

  @Override
  public void init(String keyProviderParameters) throws CryptoException {
    keyStoreConfig = KeyStoreConfig.fromParameterString(keyProviderParameters);
    
    passwords = getPasswords(conf, keyStoreConfig);
    keyStore = getKeyStore(conf, keyStoreConfig);
  }

  /**
   * Implementation of getting keys from the key store.
   */
  @Override
  public Key[] getKeys(String[] keyNames) throws CryptoException {
    if(keyStore == null)
      throw new CryptoException("Key store is not intialized.");
    
    if(keyNames == null)
      return null;
    
    Key[] rawKeys= new Key[keyNames.length];
    
    try {
      for (int i = 0; i < keyNames.length; i++) {
        String keyName = keyNames[i];
        String password = getKeyPassword(keyName);
        
        char[] passphase = null;
        if(password != null)
          passphase = password.toCharArray();
        
        Key.KeyType keyType = Key.KeyType.OPAQUE;
        String algorithm = null;
        String format = null;
        byte[] rawKey;
        
        java.security.Key key = keyStore.getKey(keyName, passphase);
        if(key != null) {
          //secret key or private key
          rawKey = key.getEncoded();
          algorithm = key.getAlgorithm();
          format = key.getFormat();
          
          if(key instanceof SecretKey) {
            keyType = Key.KeyType.SYMMETRIC_KEY;
          } else if(key instanceof PrivateKey) {
            keyType = Key.KeyType.PRIVATE_KEY;
          }
        } else {
          //trusted certificate
          Certificate certificate = keyStore.getCertificate(keyName);
          if(certificate == null)
            throw new CryptoException ("Key " + keyName + " not found");
          
          keyType = Key.KeyType.CERTIFICATE;
          rawKey = certificate.getEncoded();
        }

        rawKeys[i] = new Key (keyType, algorithm, 0, format, rawKey);
      }
    } catch(KeyStoreException e) {
      throw new CryptoException(e);
    } catch(UnrecoverableEntryException e) {
      throw new CryptoException(e);
    } catch(NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    } catch(CertificateException e) {
      throw new CryptoException(e);
    }
    
    return rawKeys;
  }
  
  /**
   * Wraps the configuration parameters for <code>KeyStoreKeyProvider</code>.
   */
  public static class KeyStoreConfig implements Writable {
    public static final String PARAM_KEYSTORE_URL = "keyStoreUrl";
    public static final String PARAM_KEYSTORE_TYPE = "keyStoreType";
    public static final String PARAM_PASSWORD = "password";
    public static final String PARAM_PASSWORD_FILE = "passwordfile";
    public static final String PARAM_SHARED_PASSWORD = "sharedPassword";
    
    private String keyStoreUrl;
    private String keyStorePassword;
    private String keyStorePasswordFile;
    private String keyStoreType;
    private boolean sharedPassword = true;
    
    /**
     * A new configuration object.
     */
    public KeyStoreConfig() {
    }
    
    /**
     * A new configuration object with specified attributes.
     */
    public KeyStoreConfig(String keyStoreUrl, String keyStoreType,
        String keyStorePassword, String keyStorePasswordFile, boolean sharedPassword) {
      super();
      this.keyStoreUrl = keyStoreUrl;
      if(StringUtils.isNotEmpty(keyStoreType)){
        this.keyStoreType = keyStoreType;
      } else {
        this.keyStoreType = DEFAULT_KEY_STORE_TYPE;
      }
      this.keyStorePassword = keyStorePassword;
      this.keyStorePasswordFile = keyStorePasswordFile;
      this.sharedPassword = sharedPassword;
    }

    /**
     * Returns the key store URL.
     */
    public String getKeyStoreUrl() {
      return keyStoreUrl;
    }
  
    /**
     * Returns the key store password for accessing the key store.
     */
    public String getKeyStorePassword() {
      return keyStorePassword;
    }

    /**
     * Returns the key store password file if the password for the key store are
     * stored in a properties file, or a per key password is needed and the per key
     * password are stored in a properties file. 
     * The property name of the password should follow the rules below:
     * 1. keystore.password is the property name of the key store password
     * 2. {keyname}.password is the property name of the per key password replacing the {keyname}
     * with the actual key name.
     */
    public String getKeyStorePasswordFile() {
      return keyStorePasswordFile;
    }

    /**
     * Specify whether the key share the same password with the key store.
     */
    public boolean isSharedPassword() {
      return sharedPassword;
    }
    
    /**
     * Specify the encryption algorithm be used to encrypt
     */
    public String getKeyStoreType(){
        return keyStoreType;
    }

    /**
     * Check whether the configuration object is valid.
     */
    public void validate() throws CryptoException {
      if(keyStoreUrl == null ||
          keyStoreUrl.isEmpty())
        throw new CryptoException("The key store YRL is not specified.");
    }

    @Override
    public void write(DataOutput out) throws IOException {
         Text.writeString(out, keyStoreUrl);
         
         if(keyStorePassword != null) {
           out.writeBoolean(true);
           Text.writeString(out, keyStorePassword);
         } else {
           out.writeBoolean(false);
         }
         
         if(keyStorePasswordFile != null) {
           out.writeBoolean(true);
           Text.writeString(out, keyStorePasswordFile);
         } else {
           out.writeBoolean(false);
         }
         
         Text.writeString(out, keyStoreType);
         
         out.writeBoolean(sharedPassword);
    }

    @Override
    public void readFields(DataInput in) throws IOException {
        keyStoreUrl = Text.readString(in);
        
        boolean hasKeyStorePassword = in.readBoolean();
        if(hasKeyStorePassword)
          keyStorePassword = Text.readString(in);
        else
          keyStorePassword = null;
        
        boolean hasKeyStorePasswordFile = in.readBoolean();
        if(hasKeyStorePasswordFile)
          keyStorePasswordFile = Text.readString(in);
        else
          keyStorePasswordFile = null;
        
        keyStoreType = Text.readString(in);
        sharedPassword = in.readBoolean();
    }
    
    /**
     * Serialize the object to a byte array.
     */
    public byte[] toBytes() throws IOException {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(outputStream);
      
      write(out);
      return outputStream.toByteArray();
    }
    
    /**
     * Deserialize to a object from the byte array.
     */
    public static KeyStoreConfig fromBytes(byte[] bytes) throws IOException {
      if(bytes == null || 
          bytes.length <= 0)
        throw new IOException("Invalid data for key store config.");
      
      ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
      DataInputStream in = new DataInputStream(inputStream);
      
      KeyStoreConfig config = new KeyStoreConfig();
      config.readFields(in);
      return config;
    }
    
    public String toParameterString() throws CryptoException {
      validate();
      
      Map<String, List<String>> parameterMap = new HashMap<String, List<String>>();
      addParameter(parameterMap, PARAM_KEYSTORE_URL, keyStoreUrl);
      addParameter(parameterMap, PARAM_KEYSTORE_TYPE, keyStoreType);
      addParameter(parameterMap, PARAM_PASSWORD, keyStorePassword);
      addParameter(parameterMap, PARAM_PASSWORD_FILE, keyStorePasswordFile);
      addParameter(parameterMap, PARAM_SHARED_PASSWORD, Boolean.toString(sharedPassword));
      
      return toUrlQueryString(parameterMap);
    }
    
    public static KeyStoreConfig fromParameterString(String parameters) throws CryptoException {
      Map<String, String[]> parameterMap = parseUrlQueryString(parameters);
      String keyStoreUrl = getParameter(parameterMap, PARAM_KEYSTORE_URL, null);
      String keyStoreType = getParameter(parameterMap, PARAM_KEYSTORE_TYPE, null);
      String keyStorePassword = getParameter(parameterMap, PARAM_PASSWORD, null);
      String keyStorePasswordFile = getParameter(parameterMap, PARAM_PASSWORD_FILE, null);
      String sharedPassword = getParameter(parameterMap, PARAM_SHARED_PASSWORD, "true");
      
      KeyStoreConfig keyStoreConfig = new KeyStoreConfig(
          keyStoreUrl, keyStoreType,
          keyStorePassword, keyStorePasswordFile, Boolean.parseBoolean(sharedPassword));
      keyStoreConfig.validate();
        
      return keyStoreConfig;
      
    }
  }

  protected KeyStore getKeyStore(Configuration conf, KeyStoreConfig keyStoreConfig) throws CryptoException  {
    String keyStoreFile = keyStoreConfig.getKeyStoreUrl();
    Path keyStorePath = new Path(keyStoreFile);
    
    try {
      FileSystem fs = keyStorePath.getFileSystem(conf);
      if(!fs.exists(keyStorePath))
        throw new CryptoException("Key store file doesn't exist. File: " + keyStoreFile);

      //read the key specified by key name from key store
      KeyStore ks = KeyStore.getInstance(keyStoreConfig.getKeyStoreType());

      // get the key store password
      String password = getKeyStorePassword();
      if(password == null ||
          password.isEmpty())
        throw new CryptoException("Key store password is not specified in any forms.");

      char[] passphase = password.toCharArray();
      InputStream in = new BufferedInputStream(fs.open(keyStorePath));
      try {
        ks.load(in, passphase);
        return ks;
      } finally {
        in.close();
      }
    } catch(IOException e) {
      throw new CryptoException(e);
    } catch(KeyStoreException e) {
      throw new CryptoException(e);
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }
  
  protected Properties getPasswords(Configuration conf, KeyStoreConfig keyStoreConfig) throws CryptoException  {
    String keyStorePasswordFile = keyStoreConfig.getKeyStorePasswordFile();
    if(keyStorePasswordFile == null ||
        keyStorePasswordFile.isEmpty())
      return null;
    
    Path keyStorePasswordPath = new Path(keyStorePasswordFile);
    
    try {
      FileSystem fs = keyStorePasswordPath.getFileSystem(conf);
      if(!fs.exists(keyStorePasswordPath))
        throw new CryptoException("Key store password file doesn't exist. File: " + keyStorePasswordFile);

      InputStream in = new BufferedInputStream(fs.open(keyStorePasswordPath));
      try {
        Properties passwords = new Properties ();
        passwords.load(in);
        return passwords;
      } finally {
        in.close();
      }
    } catch(IOException e) {
      throw new CryptoException(e);
    } catch(Exception e) {
      throw new CryptoException(e);
    }
  }
  
  protected String getKeyStorePassword() throws CryptoException {
    String password = keyStoreConfig.getKeyStorePassword();
    if(password == null) {
       if(passwords != null)
         password =  passwords.getProperty(KEY_STORE_PASSWORD_PROPERTY);
    }
    
    return password;
  }
  
  protected String getKeyPassword(String keyName) throws CryptoException {
    String password = null;
    if(keyStoreConfig.isSharedPassword()) {
      password = getKeyStorePassword();    
    } else {
      if(passwords != null)
        password = passwords.getProperty(keyName + PASSWORD_PROPERTY_SUFFIX);
    }
  
    return password;
  }
}
