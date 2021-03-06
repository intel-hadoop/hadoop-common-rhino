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

package org.apache.hadoop.security.tokenauth.api;

import java.io.IOException;

public interface AuthorizationServiceProtocol {
  /**
   * Initial version of the protocol
   */
  public static final long versionID = 1L;
  
  /**
   * Returns access token.
   * Get AccessToken for specific Hadoop service.
   * The access token is encrypted using secret key of the Hadoop service, 
   * and signed using certificate of the Hadoop service. 
   */
  byte[] getAccessToken(byte[] identityToken, String protocol) throws IOException;
}
