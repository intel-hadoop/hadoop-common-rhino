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

package org.apache.hadoop.io.crypto.splittable;

import java.io.IOException;
import java.io.InputStream;

/**
 * KMP Algorithm for string pattern match, refer to book <Introduction to Algorithm> 
 */
public final class KMP {
  int[] pi;
  byte[] pattern;
  byte[] current = new byte[1];

  public KMP(byte[] pattern) {
    this.pattern = new byte[pattern.length];
    System.arraycopy(pattern, 0, this.pattern, 0, pattern.length);
    buildPrefixFunction();
  }

  public void buildPrefixFunction() {
    int length = pattern.length;
    pi = new int[length + 1];
    pi[0] = 0;
    pi[1] = 0;
    int k = 0;
    for (int q = 1; q < length; q++) {
      while (k > 0 && pattern[k] != pattern[q]) {
        k = pi[k];
      }
      if (pattern[k] == pattern[q]) {
        k = k + 1;
      }
      pi[q + 1] = k;
    }
  }

  /**
   * return the offset of the start if a pattern has been found
   */
   public long search(byte[] input, long length) {
     int q = 0;
     for (int i = 0; i < length; i++) {
       while (q > 0 && pattern[q] != input[i]) {
         q = pi[q];
       }
       if (pattern[q] == input[i]) {
         q = q + 1;
       }
       if (q == pattern.length) {
         int found = i + 1 - pattern.length;
         return found;
       }
     }
     return -1;
   }

   /**
    * Return the offset since the beginning of the stream The stream will be
    * sought to the beginning of the matched pattern
    */
   public long search(InputStream stream) throws IOException {
     int q = 0;   

     boolean markSupported = stream.markSupported();

     if (markSupported) {
       stream.mark(2 * pattern.length);
     }
     long markPosition = 0;
     long streamPosition = 0;
     while (-1 != (stream.read(current, 0, 1))) {
       while (q > 0 && pattern[q] != current[0]) {
         q = pi[q];
       }
       if (pattern[q] == current[0]) {
         q = q + 1;
       }
       if (q == pattern.length) {
         long found = streamPosition + 1 - pattern.length;
         if (markSupported) {
           stream.reset();
           long skipped = found - markPosition;
           if(skipped < 0){
             skipped = 0;
           }
           if(stream.skip(skipped) != skipped){
             throw new IOException("Skip failed.");
           }
         }
         return found;
       }
       streamPosition++;

       if (markSupported) {
         if (q == 0) {
           stream.mark(2 * pattern.length);
           markPosition = streamPosition;
         }

         if (streamPosition - q >= markPosition + pattern.length) {
           stream.reset();
           long skipped = streamPosition - q - markPosition;
           if(skipped < 0){
             skipped = 0;
           }
           if(stream.skip(skipped) != skipped){
             throw new IOException("Skip failed.");
           }
           stream.mark(2 * pattern.length);
           markPosition = streamPosition - q;
           if(q < 0){
             q = 0;
           }
           if(stream.skip(q) != q){
             throw new IOException("Skip failed.");
           }
         }
       }
     }
     return -1;
   }
}
