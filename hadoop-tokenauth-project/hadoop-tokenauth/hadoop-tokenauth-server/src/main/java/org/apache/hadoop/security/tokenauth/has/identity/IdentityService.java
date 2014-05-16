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

package org.apache.hadoop.security.tokenauth.has.identity;

import java.io.IOException;
import java.security.Principal;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.hadoop.HadoopIllegalArgumentException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.tokenauth.api.IdentityRequest;
import org.apache.hadoop.security.tokenauth.api.IdentityResponse;
import org.apache.hadoop.security.tokenauth.has.HASConfiguration;
import org.apache.hadoop.security.tokenauth.has.HASPolicyProvider;
import org.apache.hadoop.security.tokenauth.has.identity.http.IdentityHttpServer;
import org.apache.hadoop.security.tokenauth.has.identity.rpc.IdentityRPCServer;
import org.apache.hadoop.security.tokenauth.jaas.LoginImpl;
import org.apache.hadoop.security.tokenauth.jaas.Login;
import org.apache.hadoop.security.tokenauth.jaas.session.LoginSession;
import org.apache.hadoop.security.tokenauth.jaas.session.SessionManager;
import org.apache.hadoop.security.tokenauth.secrets.Secrets;
import org.apache.hadoop.security.tokenauth.secrets.SecretsManager;
import org.apache.hadoop.security.tokenauth.token.Attribute;
import org.apache.hadoop.security.tokenauth.token.Token;
import org.apache.hadoop.security.tokenauth.token.impl.IdentityToken;
import org.apache.hadoop.security.tokenauth.token.TokenFactory;
import org.apache.hadoop.security.tokenauth.token.TokenUtils;
import org.apache.hadoop.util.GenericOptionsParser;
import org.apache.hadoop.util.Time;

public class IdentityService {
  private final static String IDENTITY_SERVICE_SECRETS = "IDENTITY_SERVICE_SECRETS";
  private Configuration conf;
  private IdentityRPCServer rpcServer;
  private IdentityHttpServer httpServer;
  private Secrets secrets;
   
  private IdentityService(Configuration conf) {
    this.conf = conf;
  }
  
  Secrets getSecrets() {
    return secrets;
  }
  
  /**
   * For RPC authentication, we don't need to keep the session after successfully login
   */
  public IdentityResponse authenticate(IdentityRequest request) throws IOException {
    return authenticate(request, null, null);
  }
  
  public IdentityResponse authenticate(IdentityRequest request, 
      HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
    LoginSession session;
    Login login;
    try {
      if(request != null && request.getSessionId() != null) {
        session = SessionManager.get().getSession(request.getSessionId());
        
        if (session == null || !session.isValid() || session.expired()) {
          login = new LoginImpl(conf, httpRequest, httpResponse);
          session = SessionManager.get().newSession(login);
        } else {
          login = session.getLogin();
          if(login == null) {
            throw new IOException("There is no associated login in the session.");
          }
          if (login.getLoginStatus() == Login.SUCCEED) {
            if(httpRequest == null) {
              session.invalidate();
            }
            return generateResponse(session.getId(), login, request.needSecrets());
          } else if (login.getLoginStatus() == Login.FAILED) {
            login = new LoginImpl(conf, httpRequest, httpResponse);
            session.setLogin(login);
          }
        }
      } else {
        login = new LoginImpl(conf, httpRequest, httpResponse);
        session = SessionManager.get().newSession(login);
      }
      
      Callback[] callbacks = request != null ? request.getCallbacks() : null;
      int result = login.login(callbacks);
      
      if(result == Login.SUCCEED) {
        String sessionId = session.getId();
        if(httpRequest == null) {
          session.invalidate();
        }
        return generateResponse(sessionId, login, request.needSecrets());
      }
      
      return new IdentityResponse(session.getId(), result, login.getFailure(), 
          login.getRequiredCallbacks());
    } catch (LoginException e) {
      throw new IOException(e);
    }
  }
  
  public byte[] renewToken(byte[] identityToken, long tokenId) throws IOException {
    throw new IOException("Renew token is not supported.");
  }
  
  public void cancelToken(byte[] identityToken, long tokenId) throws IOException {
    throw new IOException("Cancel token is not supported.");
  }
  
  /**
   * Only Authorization server can get Secrets.
   * Identity token of authorization server is signed and encrypted using Secrets of identity server.
   * Protocol indicates Hadoop service, and it equals the user principal of Hadoop service after login.
   */
  public Secrets getSecrets(byte[] tokenBytes, String protocol)  throws IOException {
    Token identityToken = TokenFactory.get().createIdentityToken(secrets, tokenBytes);
    
    String authzServerPrincipal = getAuthorizationServerPrincipal();
    String user = identityToken.getPrincipal().getName();
    if(!authzServerPrincipal.equals(user)) {
      throw new IOException("Only authorization server can get secrets from identity server");
    }
    return SecretsManager.get().getSecrets(protocol);
  }
  
  /**
   * Returns principal of Authorization server.
   */
  private String getAuthorizationServerPrincipal() throws IOException {
    String principal = conf.get(HASConfiguration.HADOOP_SECURITY_TOKENAUTH_AUTHORIZATION_SERVER_PRINCIPAL_KEY);
    if(principal == null) {
      throw new IOException("Can't get authorization server principal");
    }
    return principal;
  }
  
  /**
   * Returns authentication result.
   */
  protected IdentityResponse generateResponse(String 
      sessionId, Login login, boolean needSecrets) throws IOException {
    /**
     * If there are more than one principal, we
     * only use the first one to create identity token. 
     */
    Iterator<Principal> iter = login.getSubject().getPrincipals().iterator();
    if(!iter.hasNext()) {
      throw new IOException("There is no principal");
    }
    String user = iter.next().getName();
    
    SecretKey secretKey = null;
    PublicKey publicKey = null;
    if (needSecrets) {
      Secrets secrets = SecretsManager.get().getSecrets(user);
      secretKey = secrets.getSecretKey();
      publicKey = secrets.getPublicKey();
    }
    
    
    Token identityToken = generateIdentityToken(user, login.getAttributes());
    
    return new IdentityResponse(sessionId, Login.SUCCEED, login.getFailure(), 
        login.getRequiredCallbacks(), TokenUtils.getBytesOfToken(identityToken), 
        secretKey, publicKey);
  }
  
  /**
   * Generate Identity token after login successfully.
   * Identity token of authorization server is signed/encrypted using Secrets of Identity server.
   * Identity token of normal user or Hadoop service is signed/encrypted using Secrets of Authorization server.
   * By default, notBefore timestamp is 5 minutes, and notOnOrAfter timestamp is one day.
   */
  protected Token generateIdentityToken(String user, 
      List<Attribute> attributes) throws IOException {
    long instant = Time.now();
    long fiveMins = 5 * 60 * 1000; // in milliseconds
    long expires = conf.getLong(
        HASConfiguration.HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_EXPIRES_KEY, 
        24 * 60 * 60 * 1000); // in milliseconds
    
    String authzServerPrincipal = getAuthorizationServerPrincipal();
    Secrets secrets;
    if(user.equals(authzServerPrincipal)) {
      secrets = getSecrets();
    } else {
      secrets = SecretsManager.get().getSecrets(authzServerPrincipal);
    }
    
    boolean tokenEncrypted = conf.getBoolean(HASConfiguration.
        HADOOP_SECURITY_TOKENAUTH_IDENTITY_TOKEN_ENCRYPTED_KEY, false);
    
    Token identityToken = new IdentityToken(
        secrets, "www.apache.org", user, instant, 
        instant - fiveMins, instant + expires, tokenEncrypted);
    
    if (attributes != null)
      identityToken.getAttributes().addAll(attributes);
    
    return identityToken;
  }

  public int run(final String[] args) throws Exception {
    /* Identity server is authentication root and can be run directly. */
    return doRun(args);
  }
  
  public boolean isAlive() {
    return httpServer != null && httpServer.isAlive() && 
        rpcServer != null && rpcServer.isAlive();
  } 

  private int doRun(String[] args) throws HadoopIllegalArgumentException,
      IOException, InterruptedException {

    initIdentityServer();
    
    httpServer = new IdentityHttpServer(conf, this);
    rpcServer = new IdentityRPCServer(conf, this, new HASPolicyProvider());
    
    startHttpServer();
    startRPCServer();
    
    rpcServer.join();
    
    return 0;
  }
  
  public void stop() {
    if (rpcServer != null) {
      rpcServer.stop();
    }
    try {
      if (httpServer != null) {
        httpServer.stop();
      }
    } catch (IOException e) {
    }
  }

  private void initIdentityServer() throws HadoopIllegalArgumentException,
      IOException {
    secrets = SecretsManager.get().getSecrets(IDENTITY_SERVICE_SECRETS);
  }
  
  protected void startHttpServer() throws IOException {
    httpServer.start();
  }

  protected void startRPCServer() throws IOException {
    rpcServer.start();
  }

  public static IdentityService create(Configuration conf) {
    return new IdentityService(conf);
  }
  
  public static IdentityService create(Map<String, String> propMap) {
    Configuration conf = new HASConfiguration();
    for (Map.Entry<String, String> mapEntry : propMap.entrySet()) {
      if (mapEntry.getValue().equalsIgnoreCase("true")) {
        conf.setBoolean(mapEntry.getKey(), true);
      } else if (mapEntry.getValue().equalsIgnoreCase("false")) {
        conf.setBoolean(mapEntry.getKey(), false);
      } else {
        conf.set(mapEntry.getKey(), mapEntry.getValue());
      }
    }
    UserGroupInformation.setConfiguration(conf);
    return new IdentityService(conf);
  }

  public static void main(String args[]) throws Exception {

    GenericOptionsParser parser =
        new GenericOptionsParser(new HASConfiguration(), args);
    IdentityService identityService = 
        IdentityService.create(parser.getConfiguration());

    System.exit(identityService.run(parser.getRemainingArgs()));
  }
}