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
package org.apache.hadoop.hdfs.qjournal.protocolPB;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.qjournal.protocol.QJournalProtocolProtos.QJournalProtocolService;
import org.apache.hadoop.ipc.ProtocolInfo;
import org.apache.hadoop.security.KerberosInfo;
import org.apache.hadoop.security.tokenauth.TokenAuthInfo;

/**
 * Protocol used to journal edits to a JournalNode participating
 * in the quorum journal.
 * Note: This extends the protocolbuffer service based interface to
 * add annotations required for security.
 */
@KerberosInfo(
    serverPrincipal = DFSConfigKeys.DFS_JOURNALNODE_KERBEROS_PRINCIPAL_KEY,
    clientPrincipal = DFSConfigKeys.DFS_NAMENODE_KERBEROS_PRINCIPAL_KEY)
@TokenAuthInfo(
    serverPrincipal = DFSConfigKeys.DFS_JOURNALNODE_TOKENAUTH_USER_NAME_KEY,
    clientPrincipal = DFSConfigKeys.DFS_NAMENODE_TOKENAUTH_USER_NAME_KEY)
@ProtocolInfo(protocolName = 
    "org.apache.hadoop.hdfs.qjournal.protocol.QJournalProtocol",
    protocolVersion = 1)
@InterfaceAudience.Private
public interface QJournalProtocolPB extends
    QJournalProtocolService.BlockingInterface {
}
