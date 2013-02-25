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

import junit.framework.TestCase;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.cryptocontext.CryptoContextHelper;
import org.apache.hadoop.mapreduce.cryptocontext.provider.FileMatchCryptoContextProvider;
import org.apache.hadoop.mapreduce.cryptocontext.provider.FileMatches;
import org.apache.hadoop.mapreduce.cryptocontext.provider.KeyContext;
import org.junit.Test;

/**
 * A test for MRAsyncDiskService.
 */
public class TestFileMatchCryptoContextProvider extends TestCase {

  @Override
  protected void setUp() throws Exception {

  }

  /**
   * This test check the set and get of FileMatchCryptoContextProvider is working correctly.  
   */
  @Test(timeout=15000)
  public void testSet() throws Throwable {

    Configuration conf = new Configuration();
    Job job = Job.getInstance(conf, "test");

    JobConf jobConf = (JobConf)job.getConfiguration();

    FileMatches fileMatches = new FileMatches(KeyContext.derive("12345678"));
    fileMatches.addMatch("^.*/input1\\.intelaes$", KeyContext.derive("1234"));
    fileMatches.addMatch("^.*/input2\\.intelaes$", KeyContext.derive("5678"));

    FileMatchCryptoContextProvider.setInputCryptoContextProvider(jobConf, fileMatches, null);

    Path input1 = new Path("dfs://localhost/input/input1.intelaes");
    CryptoContext cryptoContext1 = CryptoContextHelper.getInputCryptoContext(jobConf, input1);
    assertNotNull(cryptoContext1);

    Key key1 = cryptoContext1.getKey();
    assertNotNull(key1);
    assertTrue(key1.equals(Key.derive("1234")));

    Path input2 = new Path("dfs://localhost/input/input2.intelaes");
    CryptoContext cryptoContext2 = CryptoContextHelper.getInputCryptoContext(jobConf, input2);
    assertNotNull(cryptoContext2);

    Key key2 = cryptoContext2.getKey();
    assertNotNull(key2);
    assertTrue(key2.equals(Key.derive("5678")));

    Path input3 = new Path("dfs://localhost/input/input3.intelaes");
    CryptoContext cryptoContext3 = CryptoContextHelper.getInputCryptoContext(jobConf, input3);
    assertNotNull(cryptoContext3);

    Key key3 = cryptoContext3.getKey();
    assertNotNull(key3);
    assertTrue(key3.equals(Key.derive("12345678")));
  }

}
