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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.io.crypto.CryptoException;

/**
 * <code>FileMatches</code> class defines a set of file match rules based on 
 * regular expression.  
 * If the a path string matches the regular expression of a {@link KeyContext},
 * the corresponding key context will be choose and a key will be resolved for use.
 * A default <code>KeyContext</code> can be specified for the case that the default
 * key context will be used if none of the rules are matching.
 */

public class FileMatches implements Writable {
  private KeyContext defaultKeyContext;
  private List<Match> matches = new ArrayList<Match>();

  /**
   * A match entry class which associates the regular expression
   * with a <code>KeyContext</code>
   */
  public static class Match implements Writable  {
    private Text regex;
    private KeyContext keyContext;
    private boolean matchName = false;

    private Pattern pattern;

    public Match() {
    }

    public Match(Text regex, KeyContext keyContext) {
      super();
      this.regex = regex;
      this.keyContext = keyContext;

      init();
    }

    public Match(Text regex, KeyContext key, boolean matchName) {
      super();
      this.regex = regex;
      this.keyContext = key;
      this.matchName = matchName;

      init();
    }

    private void init() {
      pattern = Pattern.compile(regex.toString());
    }

    public Text getRegex() {
      return regex;
    }

    public KeyContext getKeyContext() {
      return keyContext;
    }

    public boolean isMatchName() {
      return matchName;
    }

    public boolean isValid() {
      if(pattern == null || 
          keyContext == null)
        return false;

      return true;
    }

    public boolean matches(String uri, String name) {
      if(pattern == null)
        return false;

      String s = uri;
      if(matchName)
        s = name;

      Matcher matcher = pattern.matcher(s);
      return matcher.matches();
    }

    @Override
    public void write(DataOutput out) throws IOException {
      regex.write(out);
      keyContext.write(out);
      out.writeBoolean(matchName);
    }

    @Override
    public void readFields(DataInput in) throws IOException {
      regex = new Text();
      regex.readFields(in);

      keyContext = new KeyContext();
      keyContext.readFields(in);

      matchName = in.readBoolean();

      init();
    }
  }

  /**
   * A new file matches object.
   */
  public FileMatches() {
  }

  /**
   * A new file matches object with default key context.
   */
  public FileMatches(KeyContext defaultKey) {
    this.defaultKeyContext = defaultKey;
  }

  /**
   * Return the default key context.
   */
  public KeyContext getDefaultKeyContext() {
    return defaultKeyContext;
  }

  /**
   * Set the default key context.
   */
  public void setDefaultKeyContext(KeyContext defaultKeyContext) {
    this.defaultKeyContext = defaultKeyContext;
  }

  /**
   * Add a new match.
   * 
   * @param regex The regular expression of the match
   * @param keyContext The <code>KeyContext</code>of the match
   */
  public void addMatch(String regex, KeyContext keyContext) {
    if(regex == null ||
        keyContext == null)
      return;

    Match match = new Match(new Text(regex), keyContext);
    matches.add(match);
  }

  /**
   * Add a new match.
   * 
   * @param regex The regular expression of the match
   * @param keyContext The <code>KeyContext</code>of the match
   * @param matchName Specifies whether only matches the name other than the full path.
   */
  public void addMatch(String regex, KeyContext keyContext, boolean matchName) {
    if(regex == null ||
        keyContext == null)
      return;

    Match match = new Match(new Text(regex), keyContext, matchName);
    matches.add(match);
  }

  /**
   * Add a new match.
   * 
   * @param match The match to be added
   */
  public void addMatch(Match match) {
    if(match == null ||
        !match.isValid())
      return;

    matches.add(match);
  }

  /**
   * Return the list of the matches.
   */
  public List<Match> getMatches() {
    return matches;
  }

  /**
   * The function to do the match with a file and returns
   * the <code>KeyContext</code> that matches. The default key context will be used
   * if none of the rules match.
   */
  public KeyContext getMatchedKey(Path file) {
    if(file == null ||
        matches == null ||
        matches.isEmpty())
      return getDefaultKeyContext();

    String uri = file.toString();
    String name = file.getName();

    for(Match match : matches) {
      if(match.matches(uri, name))
        return match.getKeyContext();
    }

    return getDefaultKeyContext();
  }

  @Override
  public void write(DataOutput out) throws IOException {
    //write the defaut key context
    if(defaultKeyContext == null ||
        !defaultKeyContext.isValid()) {
      out.writeBoolean(false);
    } else {
      out.writeBoolean(true);
      defaultKeyContext.write(out);
    }

    // write out the matches
    WritableUtils.writeVInt(out, matches.size());
    for(Match match : matches) {
      match.write(out);
    }
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    //read default key context
    defaultKeyContext = null;

    boolean defaultKeyPresent = in.readBoolean();
    if(defaultKeyPresent) {
      defaultKeyContext = new KeyContext();
      defaultKeyContext.readFields(in);
    }

    //read the matches
    int size = WritableUtils.readVInt(in);
    for(int i=0; i<size; i++) {
      Match match = new Match();
      match.readFields(in);
      matches.add(match);
    }
  }

  /**
   * Serialize the object to byte array.
   */
  public byte[] toBytes() throws CryptoException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(outputStream);

    try {
      write(out);
    } catch (IOException e) {
      throw new CryptoException(e);
    }

    return outputStream.toByteArray();
  }

  /**
   * Deserialize the object from a byte array
   */
  public static FileMatches from(byte[] secrets) throws IOException {
    if(secrets == null || 
        secrets.length <= 0)
      return null;

    ByteArrayInputStream inputStream = new ByteArrayInputStream(secrets);
    DataInputStream in = new DataInputStream(inputStream);

    FileMatches fileMatches = new FileMatches();
    fileMatches.readFields(in);
    return fileMatches;
  }


}
