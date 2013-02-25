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

package org.apache.hadoop.tools;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Stack;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.protocol.QuotaExceededException;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.SequenceFile;
import org.apache.hadoop.io.SequenceFile.CompressionType;
import org.apache.hadoop.io.SequenceFile.Metadata;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.Writable;
import org.apache.hadoop.io.WritableComparable;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.DefaultCodec;
import org.apache.hadoop.io.crypto.CryptoCodec;
import org.apache.hadoop.io.crypto.CryptoContext;
import org.apache.hadoop.io.crypto.CryptoException;
import org.apache.hadoop.io.crypto.Key;
import org.apache.hadoop.io.crypto.aes.AESCodec;
import org.apache.hadoop.ipc.RemoteException;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.FileSplit;
import org.apache.hadoop.mapred.InputFormat;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.InvalidInputException;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.SequenceFileRecordReader;
import org.apache.hadoop.mapreduce.Counter;
import org.apache.hadoop.mapreduce.Counters;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.JobSubmissionFiles;
import org.apache.hadoop.mapreduce.MapContext;
import org.apache.hadoop.mapreduce.task.MapContextImpl;
import org.apache.hadoop.mapreduce.StatusReporter;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.task.TaskAttemptContextImpl;
import org.apache.hadoop.mapreduce.TaskAttemptID;
import org.apache.hadoop.mapreduce.TaskType;
import org.apache.hadoop.mapreduce.cryptocontext.CryptoContextHelper;
import org.apache.hadoop.mapreduce.cryptocontext.provider.FileMatchCryptoContextProvider;
import org.apache.hadoop.mapreduce.cryptocontext.provider.FileMatches;
import org.apache.hadoop.mapreduce.cryptocontext.provider.KeyContext;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.SequenceFileAsBinaryInputFormat;
import org.apache.hadoop.mapreduce.lib.input.SequenceFileAsBinaryInputFormat.SequenceFileAsBinaryRecordReader;
import org.apache.hadoop.mapreduce.lib.output.SequenceFileAsBinaryOutputFormat;
import org.apache.hadoop.mapreduce.security.TokenCache;
import org.apache.hadoop.security.AccessControlException;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.util.ReflectionUtils;
import org.apache.hadoop.util.StringUtils;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;
import org.apache.hadoop.util.StringUtils.TraditionalBinaryPrefix;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


/**
 * A Map-reduce program to recursively encrypt, decrypt or rotate files in directories between
 * different file-systems.
 */
public class DistCrypto implements Tool {
  public static final Log LOG = LogFactory.getLog(DistCrypto.class);

  private static final String NAME = "distcrypto";

  private static final String usage = NAME
    + " [OPTIONS]" +
    "\n\nOPTIONS:" +
    "\n-op <operation>        Operation to perform, must be one of the following: " +
    "\n                       encrypt: encrypt the files with the encryption key" +
    "\n                       decrypt: decrypt the files with the decryption key" +
    "\n                       rotate:  decrypt the files with the decryption key and encrypt the files with the encryption key" +
    "\n-ek <encryptionKey>    Hex encoded encryption key" +
    "\n-dk <decryptionKey>    Hex encoded decryption key" +
    "\n-src <srclist>         Use list at <srclist> as src list" +
    "\n-dst <dsturl>          Target url for encrypted or decrypted files" +
    "\n                       If not specified, the target file will be in the same folder as the src file" +
    "\n-log <logurl>          Write logs to <logurl>" +
    "\n-p[rbugp]              Preserve status" +
    "\n                       r: replication number" +
    "\n                       b: block size" +
    "\n                       u: user" + 
    "\n                       g: group" +
    "\n                       p: permission" +
    "\n                       -p alone is equivalent to -prbugp" +
    "\n-i                     Ignore failures" +
    "\n-m <maxtasks>          Maximum number of simultaneous tasks" +
    "\n-sslConf <file>        Filename of SSL configuration for mapper task" +
    "\n[srcurl]               Source url which contains the source files to perform the operation" +
    "\n                       By default, it assumes the files are RAW format and .<operation> will be appended to form a new file name" +
    "\n                       Use <srclist> to specify mutliple source urls and advanded options for each url." +
    "\n";
  
  public static interface CryptoProgressReporter {
    void reportProgress(String progress);
    
    Reporter getReporter();
  }
  
  public static interface CryptoHandler {
    
    void configure(JobConf job, EnumSet<FileAttribute> preserved);
    
    long encryptFile(Key encryptionKey, 
        FileStatus src, Path dst, FileSystem dstfs, 
        CryptoProgressReporter reporter) throws IOException;

    long decryptFile(Key decryptionKey, 
        FileStatus src, Path dst, FileSystem dstfs, 
        CryptoProgressReporter reporter) throws IOException;

    long rotateFile(Key decryptionKey, Key encryptionKey,
        FileStatus src, Path dst, FileSystem dstfs, 
        CryptoProgressReporter reporter) throws IOException;
  }
  
  public static enum FileAttribute {
    BLOCK_SIZE, REPLICATION, USER, GROUP, PERMISSION;

    final char symbol;

    private FileAttribute() {symbol = toString().toLowerCase().charAt(0);}
    
    static EnumSet<FileAttribute> parse(String s) {
      if (s == null || s.length() == 0) {
        return EnumSet.allOf(FileAttribute.class);
      }

      EnumSet<FileAttribute> set = EnumSet.noneOf(FileAttribute.class);
      FileAttribute[] attributes = values();
      for(char c : s.toCharArray()) {
        int i = 0;
        for(; i < attributes.length && c != attributes[i].symbol; i++);
        if (i < attributes.length) {
          if (!set.contains(attributes[i])) {
            set.add(attributes[i]);
          } else {
            throw new IllegalArgumentException("There are more than one '"
                + attributes[i].symbol + "' in " + s); 
          }
        } else {
          throw new IllegalArgumentException("'" + c + "' in " + s
              + " is undefined.");
        }
      }
      return set;
    }
  }
  
  private static final long BYTES_PER_MAP =  256 * 1024 * 1024;
  private static final int MAX_MAPS_PER_NODE = 20;
  private static final int SYNC_FILE_MAX = 10;
  
  static enum Operation {
    ENCRYPT("encrypt"),
    DECRYPT("decrypt"),
    ROTATE("rotate");
    
    private String cmd;
    
    private Operation(String cmd) {
      this.cmd = cmd;
    }
    
    public static Operation parseOperation(String cmd) {
      for(Operation op : Operation.values()) {
        if(op.cmd.equalsIgnoreCase(cmd))
          return op;
      }
      
      throw new IllegalArgumentException("Invalid operation: " + cmd);
    }
    
    public String getCmd() {
      return cmd;
    }
  }

  static enum CryptoCounter { PROCESSED_FILES, SKIP_FILES, FAIL_FILES, PROCESSED_BYTES; }
  
  static enum Options {
    IGNORE_READ_FAILURES("-i", NAME + ".ignore.read.failures"),
    PRESERVE_STATUS("-p", NAME + ".preserve.status");

    final String cmd, propertyname;

    private Options(String cmd, String propertyname) {
      this.cmd = cmd;
      this.propertyname = propertyname;
    }
  }
  
  static private class SrcOptions implements Writable {
    public static final String RAW_FORMAT = "raw";
    public static final String SEQUENCE_FORMAT = "sequence";
    
    private String format = RAW_FORMAT;
    
    private String includeFilter = "";
    private String excludeFilter = "";
    
    private String stripSuffix = "";
    private String appendSuffix = "";
    
    private String keyClassName = "";
    private String valueClassName = "";
    
    private Pattern includePattern = null;
    private Pattern excludePattern = null;
    
    public SrcOptions() {
      
    }
    
    public SrcOptions(String format, 
        String includeFilter, String excludeFilter,
        String stripSuffix, String appendSuffix,
        String keyClassName, String valueClassName) {
      if(format == null || 
          format.isEmpty())
        format = RAW_FORMAT;
      
      if(includeFilter == null)
        includeFilter = "";
      
      if(excludeFilter == null)
        excludeFilter = "";
      
      if(stripSuffix == null)
        stripSuffix = "";
      
      if(appendSuffix == null)
        appendSuffix = "";
      
      if(keyClassName == null)
        keyClassName = "";
      
      if(valueClassName == null)
        valueClassName = "";
      
      this.format = format;
      
      this.includeFilter = includeFilter;
      this.excludeFilter = excludeFilter;
      
      this.stripSuffix = stripSuffix;
      this.appendSuffix = appendSuffix;
      
      this.keyClassName = keyClassName;
      this.valueClassName = valueClassName;
      
      init();
    }
    
    private void init() {
      if(includeFilter != null &&
          !includeFilter.isEmpty()) {
        includePattern = Pattern.compile(includeFilter.toString());
      }
      
      if(excludeFilter != null &&
          !excludeFilter.isEmpty()) {
        excludePattern = Pattern.compile(excludeFilter.toString());
      }
    }

    public String getFormat() {
      return format;
    }

    public String getStripSuffix() {
      return stripSuffix;
    }

    public String getAppendSuffix() {
      return appendSuffix;
    }

    public boolean isRawFormat() {
      if(RAW_FORMAT.equals(format))
        return true;
      
      return false;
    }
    
    public boolean isSequenceFormat() {
      if(SEQUENCE_FORMAT.equals(format))
        return true;
      
      return false;
    }
    
    public boolean isMatch(String name) {
      if(includePattern != null) {
        Matcher matcher = includePattern.matcher(name);
        if(!matcher.matches())
          return false;
      }
      
      if(excludePattern != null) {
        Matcher matcher = excludePattern.matcher(name);
        if(matcher.matches())
          return false;
      }
     
      return true;
    }
    
    public void validate(Configuration conf) throws IllegalArgumentException {
      if(isRawFormat()) {
        //do any checks here
      } else if(isSequenceFormat()) {
        if(!keyClassName.isEmpty()) {
          try {
            conf.getClassByName(keyClassName);
          } catch(ClassNotFoundException e) {
            throw new IllegalArgumentException("Key class '" + keyClassName + "' you specified is not found. " +
            		"Please use -libjars option to add it's jar to class path.");
          }
        }
        
        if(!valueClassName.isEmpty()) {
          try {
            conf.getClassByName(valueClassName);
          } catch(ClassNotFoundException e) {
            throw new IllegalArgumentException("Value class '" + valueClassName + "' you specified is not found. " +
            		"Please use -libjars option to add it's jar to class path.");
          }
        }
      } else {
        if(format.isEmpty())
            throw new IllegalArgumentException("Format is not specified.");

        try {
          Class<?> clz = conf.getClassByName(format);
          ReflectionUtils.newInstance(clz, conf);
        } catch(ClassNotFoundException e) {
          throw new IllegalArgumentException("Format class '" + format + "' you specified is not found. " +
              "Please use -libjars option to add it's jar to class path.");
        }
      }
      
    }

    public void readFields(DataInput in) throws IOException {
      format = Text.readString(in);
      includeFilter = Text.readString(in);
      excludeFilter = Text.readString(in);
      stripSuffix = Text.readString(in);
      appendSuffix = Text.readString(in);
      keyClassName = Text.readString(in);
      valueClassName = Text.readString(in);
      
      init();
    }
    
    public void write(DataOutput out) throws IOException {
      Text.writeString(out, format);
      Text.writeString(out, includeFilter);
      Text.writeString(out, excludeFilter);
      Text.writeString(out, stripSuffix);
      Text.writeString(out, appendSuffix);
      Text.writeString(out, keyClassName);
      Text.writeString(out, valueClassName);
    }
    
    public String toString() {
      StringBuffer sb = new StringBuffer();
      
      sb.append("format=").append(format);
      
      if(!includeFilter.isEmpty())
        sb.append(", includeFilter=").append(includeFilter);
      
      if(!excludeFilter.isEmpty())
        sb.append(", excludeFilter=").append(excludeFilter);
      
      if(!stripSuffix.isEmpty())
        sb.append(", stripSuffix=").append(stripSuffix);
      
      if(!appendSuffix.isEmpty())
        sb.append(", appendSuffix=").append(appendSuffix);
      
      if(!keyClassName.isEmpty())
        sb.append(", keyClassName=").append(keyClassName);
      
      if(!valueClassName.isEmpty())
        sb.append(", valueClassName=").append(valueClassName);
      
      return sb.toString();
    }
  }
  
  static private class SrcItem implements Writable {
    private Path path;
    private SrcOptions options;
    
    public SrcItem(Path path, SrcOptions options) {
      super();
      this.path = path;
      this.options = options;
    }

    public Path getPath() {
      return path;
    }
    
    public SrcOptions getOptions() {
      return options;
    }

    public void readFields(DataInput in) throws IOException {
      String strPath = Text.readString(in);
      this.path = new Path(strPath);
      options = new SrcOptions();
      options.readFields(in);
    }
    
    public void write(DataOutput out) throws IOException {
      Text.writeString(out, getPath().toString());
      options.write(out);
    }
    
    public String toString() {
      return path + " {" + options + "}";
    }
  }
  
  static private class Arguments {
    final List<SrcItem> srcs;
    final Path dst;
    final Operation operation;
    final Key encryptionKey;
    final Key decryptionKey;
    final Path log;
    final EnumSet<Options> flags;
    final String preservedAttributes;
    final String sslConf;
    
    /**
     * Arguments for this tool
     * @param srcs List of source paths
     * @param dst Destination path
     * @param log Log output directory
     * @param flags Command-line flags
     * @param preservedAttributes Preserved attributes 
     * @param filelimit File limit
     * @param sizelimit Size limit
     */
    Arguments(List<SrcItem> srcs, Path dst, Operation operation, Key encryptionKey, Key decryptionKey,
        Path log, EnumSet<Options> flags, String preservedAttributes, String sslConf) {
      this.srcs = srcs;
      this.dst = dst;
      
      this.operation = operation;
      this.encryptionKey = encryptionKey;
      this.decryptionKey = decryptionKey;
      
      this.log = log;
      this.flags = flags;
      this.preservedAttributes = preservedAttributes;
      
      this.sslConf = sslConf;
      
      if (LOG.isTraceEnabled()) {
        LOG.trace("this = " + this);
      }
    }

    static Arguments valueOf(String[] args, Configuration conf
        ) throws IOException {
      Operation operation = null;
      Key encryptionKey = null;
      Key decryptionKey = null;
      List<SrcItem> srcs = new ArrayList<SrcItem>();
      Path dst = null;
      Path log = null;
      EnumSet<Options> flags = EnumSet.noneOf(Options.class);
      String presevedAttributes = null;
      String sslConf = null;
      String defaultAppendPrefix = null;

      for (int idx = 0; idx < args.length; idx++) {
        //locate if it is in Options
        Options[] opt = Options.values();
        int i = 0;
        for(; i < opt.length && !args[idx].startsWith(opt[i].cmd); i++);

        if (i < opt.length) {
          //if it is a Option
          flags.add(opt[i]);
          if (opt[i] == Options.PRESERVE_STATUS) {
            presevedAttributes =  args[idx].substring(2);         
            FileAttribute.parse(presevedAttributes); //validation
          }
        } else if ("-op".equals(args[idx])) {
          if (++idx ==  args.length) {
            throw new IllegalArgumentException("operation not specified in -op");
          }
          operation = Operation.parseOperation(args[idx]);
          defaultAppendPrefix = "." + args[idx];
        } else if ("-ek".equals(args[idx])) {
          if (++idx ==  args.length) {
            throw new IllegalArgumentException("encryptionkey not specified in -ek");
          }
          encryptionKey = parseKey(args[idx]);
        } else if ("-dk".equals(args[idx])) {
          if (++idx ==  args.length) {
            throw new IllegalArgumentException("decryptionkey not specified in -dk");
          }
          decryptionKey = parseKey(args[idx]);
        } else if ("-src".equals(args[idx])) {
          if (++idx ==  args.length) {
            throw new IllegalArgumentException("srclist not specified in -src");
          }
          srcs.addAll(parseSrcItems(conf, new Path(args[idx])));
        } else if ("-dst".equals(args[idx])) {
          if (++idx ==  args.length) {
            throw new IllegalArgumentException("dsturl not specified in -dst");
          }
          dst = new Path(args[idx]);
        } else if ("-log".equals(args[idx])) {
          if (++idx ==  args.length) {
            throw new IllegalArgumentException("logurl not specified in -log");
          }
          log = new Path(args[idx]);
        } else if ("-sslConf".equals(args[idx])) {
          if (++idx ==  args.length) {
            throw new IllegalArgumentException("file not specified in -sslConf");
          }
          sslConf = args[idx];
        } else if ("-m".equals(args[idx])) {
          if (++idx == args.length) {
            throw new IllegalArgumentException("maxtasks not specified in -m");
          }
          try {
            conf.setInt(MAX_MAPS_LABEL, Integer.valueOf(args[idx]));
          } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid argument to -m: " +
                                               args[idx]);
          }
        } else if ('-' == args[idx].codePointAt(0)) {
          throw new IllegalArgumentException("Invalid switch " + args[idx]);
        } else {
          SrcOptions srcOptions = new SrcOptions(null,
              null, null, 
              null, defaultAppendPrefix,
              null, null);
          SrcItem srcItem = new SrcItem(new Path(args[idx]), srcOptions);
          srcs.add(srcItem);
        }
      }
      
      // mandatory command-line parameters
      if (srcs.isEmpty()) {
        throw new IllegalArgumentException("No src specified.");
      }
      
      if(operation == null) {
        throw new IllegalArgumentException("No operation specified. Operation must be encrypt, decrypt or rotate.");
      }
      
      if (operation == Operation.ENCRYPT ||
          operation == Operation.ROTATE) {
          if (encryptionKey == null || !encryptionKey.isValid()) {
            throw new IllegalArgumentException("Encryption key is not specified for encrypt operation.");
          }
      }
          
      if (operation == Operation.DECRYPT ||
          operation == Operation.ROTATE) {
          if (decryptionKey == null || !decryptionKey.isValid()) {
            throw new IllegalArgumentException("Decryption key is not specified for decrypt operation.");
          }
      }
      
      //check validation
      if(dst == null && log == null) {
        throw new IllegalArgumentException("logurl must be specified if dsturl is not specified.");
      }
      
      return new Arguments(srcs, dst, 
          operation, encryptionKey, decryptionKey,
          log, flags, presevedAttributes, sslConf);
    }
    
    /** {@inheritDoc} */
    public String toString() {
      return getClass().getName() + "{"
          + "\n  operation = " +  operation
          + "\n  encryptionKey = " +  encryptionKey
          + "\n  decryptionKey = " +  decryptionKey
          + "\n  srcs = " + srcs 
          + "\n  dst = " + dst
          + "\n  log = " + log 
          + "\n  flags = " + flags
          + "\n  preservedAttributes = " + preservedAttributes 
          + "\n  sslConf = " + sslConf
          + "\n}"; 
    }
  }
  
  /** An exception class for duplicated source files. */
  public static class DuplicationException extends IOException {
    private static final long serialVersionUID = 1L;
    /** Error code for this exception */
    public static final int ERROR_CODE = -2;
    DuplicationException(String message) {super(message);}
  }
  
  /**
   * An input/output pair of filenames.
   */
  static class FilePair implements Writable {
    FileStatus input = new FileStatus();
    String output;
    SrcOptions options = new SrcOptions();
    
    FilePair() { 
    }
    
    FilePair(FileStatus input, String output, SrcOptions options) {
      this.input = input;
      this.output = output;
      this.options = options;
    }
    
    public void readFields(DataInput in) throws IOException {
      input.readFields(in);
      output = Text.readString(in);
      options = new SrcOptions();
      options.readFields(in);
    }
    
    public void write(DataOutput out) throws IOException {
      input.write(out);
      Text.writeString(out, output);
      options.write(out);
    }
    
    public String toString() {
      return input + " : " + output;
    }
  }

  static final String OPERATION_LABEL = NAME + ".operation";
  static final String ENCRYPTION_KEY_LABEL = NAME + ".encryption.key";
  static final String DECRYPTION_KEY_LABEL = NAME + ".decryption.key";
  
  static final String TMP_DIR_LABEL = NAME + ".tmp.dir";
  static final String DST_DIR_LABEL = NAME + ".dest.path";
  static final String JOB_DIR_LABEL = NAME + ".job.dir";
  
  static final String MAX_MAPS_LABEL = NAME + ".max.map.tasks";
  static final String SRC_LIST_LABEL = NAME + ".src.list";
  static final String SRC_COUNT_LABEL = NAME + ".src.count";
  static final String TOTAL_SIZE_LABEL = NAME + ".total.size";
  static final String DST_DIR_LIST_LABEL = NAME + ".dst.dir.list";
  static final String BYTES_PER_MAP_LABEL = NAME + ".bytes.per.map";
  static final String PRESERVE_STATUS_LABEL
      = Options.PRESERVE_STATUS.propertyname + ".value";

  private JobConf conf;

  public void setConf(Configuration conf) {
    if (conf instanceof JobConf) {
      this.conf = (JobConf) conf;
    } else {
      this.conf = new JobConf(conf);
    }
  }

  public Configuration getConf() {
    return conf;
  }

  public DistCrypto(Configuration conf) {
    setConf(conf);
  }



  private static List<SrcItem> parseSrcItems(Configuration conf, Path srcList)
      throws IOException {
    try {
      DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
      //ignore all comments inside the xml file
      docBuilderFactory.setIgnoringComments(true);
  
      //allow includes in the xml file
      docBuilderFactory.setNamespaceAware(true);
      
      try {
        docBuilderFactory.setXIncludeAware(true);
      } catch (UnsupportedOperationException e) {
        LOG.error("Failed to set setXIncludeAware(true) for parser "
            + docBuilderFactory
            + ":" + e,
            e);
      }
      
      DocumentBuilder builder = docBuilderFactory.newDocumentBuilder();
      Document doc = null;
  
      FileSystem fs = srcList.getFileSystem(conf);
      InputStream in = new BufferedInputStream(fs.open(srcList));
      try {
        doc = builder.parse(in);
      } finally {
        in.close();
      }
      
      Element root = doc.getDocumentElement();
      
      List<SrcItem> result = new ArrayList<SrcItem>();
      
      NodeList srcNodes = root.getChildNodes();
      for (int i = 0; i < srcNodes.getLength(); i++) {
        Node srcNode = srcNodes.item(i);
        if (!(srcNode instanceof Element))
          continue;
        
        Element src = (Element)srcNode;
        if (!"src".equals(src.getTagName())) {
          LOG.warn("Bad src list file: element not <src>.");
          continue;
        }
        
        NodeList fields = src.getChildNodes();
        
        String path = null;
        
        String format = null;
        
        String includeFilter = null;
        String excludeFilter = null;
        
        String stripSuffix = null;
        String appendSuffix = null;
        
        String keyClassName = null;
        String valueClassName = null;
        
        for (int j = 0; j < fields.getLength(); j++) {
          Node fieldNode = fields.item(j);
          if (!(fieldNode instanceof Element))
            continue;
          
          Element field = (Element)fieldNode;
          if(!field.hasChildNodes())
            continue;
          
          String tagName = field.getTagName();
          if ("path".equals(tagName))
            path = ((org.w3c.dom.Text)field.getFirstChild()).getData().trim();
          else if ("format".equals(tagName))
            format = ((org.w3c.dom.Text)field.getFirstChild()).getData().trim();
          else if ("includeFilter".equals(tagName))
            includeFilter = ((org.w3c.dom.Text)field.getFirstChild()).getData();
          else if ("excludeFilter".equals(tagName))
            excludeFilter = ((org.w3c.dom.Text)field.getFirstChild()).getData();
          else if ("stripSuffix".equals(tagName))
            stripSuffix = ((org.w3c.dom.Text)field.getFirstChild()).getData();
          else if ("appendSuffix".equals(tagName))
            appendSuffix = ((org.w3c.dom.Text)field.getFirstChild()).getData();
          else if ("keyClassName".equals(tagName))
            keyClassName = ((org.w3c.dom.Text)field.getFirstChild()).getData();
          else if ("valueClassName".equals(tagName))
            valueClassName = ((org.w3c.dom.Text)field.getFirstChild()).getData();
        }
        
        if(path == null || path.isEmpty()) {
          LOG.warn("Bad src list file: <src> has empty <path>.");
          continue;
        }
        
        SrcOptions srcOptions = new SrcOptions(format, 
            includeFilter, excludeFilter, 
            stripSuffix, appendSuffix,
            keyClassName, valueClassName);
        SrcItem srcItem = new SrcItem(new Path(path), srcOptions);
        result.add(srcItem);
      }
      
      return result;
    } catch (IOException e) {
      LOG.fatal("Error parsing src list file: " + e);
      throw e;
    } catch (DOMException e) {
      LOG.fatal("Error parsing src list file: " + e);
      throw new IOException(e);
    } catch (SAXException e) {
      LOG.fatal("Error parsing src list file: " + e);
      throw new IOException(e);
    } catch (ParserConfigurationException e) {
      LOG.fatal("Error parsing src list file: " + e);
      throw new IOException(e);
    }
  }

  /** Sanity check for srcPath */
  private static void checkSrcPath(JobConf jobConf, List<SrcItem> srcItems)
      throws IOException {
    List<IOException> rslt = new ArrayList<IOException>();
    
    Path[] ps = new Path[srcItems.size()];
    int i = 0;
    for (SrcItem src : srcItems) {
      ps[i] = src.getPath();
      i++;
    }
    
    TokenCache.obtainTokensForNamenodes(jobConf.getCredentials(), ps, jobConf);

    for (SrcItem src : srcItems) {
      Path p = src.getPath();
      FileSystem fs = p.getFileSystem(jobConf);
      if (!fs.exists(p)) {
        rslt.add(new IOException("Input source " + p + " does not exist."));
      }
    }
    
    if (!rslt.isEmpty()) {
      throw new InvalidInputException(rslt);
    }
  }

  /**
   * Driver to encrypt, decrypt or rotate srcs (to dstDir) depending on required protocol.
   * @param args arguments
   */
  static void crypto(final Configuration conf, final Arguments args
      ) throws IOException {
    LOG.info("Operation: " + args.operation.getCmd());
    LOG.info("Sources: " + args.srcs);
    LOG.info("Destination: " + (args.dst == null ? "" : args.dst));

    JobConf job = createJobConf(conf);
    
    checkSrcPath(job, args.srcs);
    if (args.preservedAttributes != null) {
      job.set(PRESERVE_STATUS_LABEL, args.preservedAttributes);
    }
    if (args.sslConf != null) {
      job.set("dfs.https.client.keystore.resource", args.sslConf);
    }
    
    //Initialize the mapper
    try {
      if (setup(conf, job, args)) {
        JobClient.runJob(job);
      }
      finalize(conf, job, args.dst, args.preservedAttributes);
    } finally {
      //delete tmp
      fullyDelete(job.get(TMP_DIR_LABEL), job);
      //delete jobDirectory
      fullyDelete(job.get(JOB_DIR_LABEL), job);
    }
  }

  private static void updatePermissions(FileStatus src, FileStatus dst,
      EnumSet<FileAttribute> preseved, FileSystem destFileSys
      ) throws IOException {
    String owner = null;
    String group = null;
    if (preseved.contains(FileAttribute.USER)
        && !src.getOwner().equals(dst.getOwner())) {
      owner = src.getOwner();
    }
    if (preseved.contains(FileAttribute.GROUP)
        && !src.getGroup().equals(dst.getGroup())) {
      group = src.getGroup();
    }
    if (owner != null || group != null) {
      destFileSys.setOwner(dst.getPath(), owner, group);
    }
    if (preseved.contains(FileAttribute.PERMISSION)
        && !src.getPermission().equals(dst.getPermission())) {
      destFileSys.setPermission(dst.getPath(), src.getPermission());
    }
  }

  @SuppressWarnings("deprecation")
  static private void finalize(Configuration conf, JobConf jobconf,
      final Path dstDir, String presevedAttributes) throws IOException {
    if (presevedAttributes == null) {
      return;
    }
    EnumSet<FileAttribute> preseved = FileAttribute.parse(presevedAttributes);
    if (!preseved.contains(FileAttribute.USER)
        && !preseved.contains(FileAttribute.GROUP)
        && !preseved.contains(FileAttribute.PERMISSION)) {
      return;
    }

    FileSystem dstfs = dstDir.getFileSystem(conf);
    Path dstdirlist = new Path(jobconf.get(DST_DIR_LIST_LABEL));
    SequenceFile.Reader in = null;
    try {
      in = new SequenceFile.Reader(dstdirlist.getFileSystem(jobconf),
          dstdirlist, jobconf);
      Text dsttext = new Text();
      FilePair pair = new FilePair(); 
      for(; in.next(dsttext, pair); ) {
        Path dstpath = new Path(dstDir, pair.output);
        updatePermissions(pair.input, dstfs.getFileStatus(dstpath),
            preseved, dstfs);
      }
    } finally {
      checkAndClose(in);
    }
  }
  
  

  /**
   * This is the main driver for recursively copying directories
   * across file systems. It takes at least two cmdline parameters. A source
   * URL and a destination URL. It then essentially does an "ls -lR" on the
   * source URL, and writes the output in a round-robin manner to all the map
   * input files. The mapper actually copies the files allotted to it. The
   * reduce is empty.
   */
  public int run(String[] args) {
    try {
      crypto(conf, Arguments.valueOf(args, conf));
      return 0;
    } catch (IllegalArgumentException e) {
      System.err.println(StringUtils.stringifyException(e) + "\n" + usage);
      ToolRunner.printGenericCommandUsage(System.err);
      return -1;
    } catch (DuplicationException e) {
      System.err.println(StringUtils.stringifyException(e));
      return DuplicationException.ERROR_CODE;
    } catch (RemoteException e) {
      final IOException unwrapped = e.unwrapRemoteException(
          FileNotFoundException.class, 
          AccessControlException.class,
          QuotaExceededException.class);
      System.err.println(StringUtils.stringifyException(unwrapped));
      return -3;
    } catch (Exception e) {
      System.err.println("With failures, global counters are inaccurate; " +
          "consider running with -i");
      System.err.println("Crypto failed: " + StringUtils.stringifyException(e));
      return -999;
    }
  }

  public static void main(String[] args) throws Exception {
    JobConf job = new JobConf(DistCrypto.class);
    DistCrypto distcp = new DistCrypto(job);
    int res = ToolRunner.run(distcp, args);
    System.exit(res);
  }

  /**
   * Make a path relative with respect to a root path.
   * absPath is always assumed to descend from root.
   * Otherwise returned path is null.
   */
  static String makeRelative(Path root, Path absPath) {
    if (!absPath.isAbsolute()) {
      throw new IllegalArgumentException("absPath not absolute path, absPath="
          + absPath);
    }
    String p = absPath.toUri().getPath();

    StringTokenizer pathTokens = new StringTokenizer(p, "/");
    for(StringTokenizer rootTokens = new StringTokenizer(
        root.toUri().getPath(), "/"); rootTokens.hasMoreTokens(); ) {
      if (!rootTokens.nextToken().equals(pathTokens.nextToken())) {
        return null;
      }
    }
    StringBuilder sb = new StringBuilder();
    for(; pathTokens.hasMoreTokens(); ) {
      sb.append(pathTokens.nextToken());
      if (pathTokens.hasMoreTokens()) { sb.append(Path.SEPARATOR); }
    }
    return sb.length() == 0? ".": sb.toString();
  }

  /**
   * Calculate how many maps to run.
   * Number of maps is bounded by a minimum of the cumulative size of the
   * process / (distcp.bytes.per.map, default BYTES_PER_MAP or -m on the
   * command line) and at most (distcp.max.map.tasks, default
   * MAX_MAPS_PER_NODE * nodes in the cluster).
   * @param totalBytes Count of total bytes for job
   * @param job The job to configure
   * @return Count of maps to run.
   */
  private static void setMapCount(long totalBytes, JobConf job) 
      throws IOException {
    int numMaps =
      (int)(totalBytes / job.getLong(BYTES_PER_MAP_LABEL, BYTES_PER_MAP));
    numMaps = Math.min(numMaps, 
        job.getInt(MAX_MAPS_LABEL, MAX_MAPS_PER_NODE *
          new JobClient(job).getClusterStatus().getTaskTrackers()));
    job.setNumMapTasks(Math.max(numMaps, 1));
  }

  /** Fully delete dir */
  static void fullyDelete(String dir, Configuration conf) throws IOException {
    if (dir != null) {
      Path tmp = new Path(dir);
      tmp.getFileSystem(conf).delete(tmp, true);
    }
  }

  //Job configuration
  private static JobConf createJobConf(Configuration conf) {
    JobConf jobconf = new JobConf(conf, DistCrypto.class);
    jobconf.setJobName(NAME);

    // turn off speculative execution, because DFS doesn't handle
    // multiple writers to the same file.
    jobconf.setMapSpeculativeExecution(false);

    jobconf.setInputFormat(CryptoInputFormat.class);
    jobconf.setOutputKeyClass(Text.class);
    jobconf.setOutputValueClass(Text.class);

    jobconf.setMapperClass(CryptoFilesMapper.class);
    jobconf.setNumReduceTasks(0);
    return jobconf;
  }

  private static final Random RANDOM = new Random();
  public static String getRandomId() {
    return Integer.toString(RANDOM.nextInt(Integer.MAX_VALUE), 36);
  }

  /**
   * Initialize DFSCopyFileMapper specific job-configuration.
   * @param conf : The dfs/mapred configuration.
   * @param jobConf : The handle to the jobConf object to be initialized.
   * @param args Arguments
   * @return true if it is necessary to launch a job.
   */
  @SuppressWarnings("deprecation")
  private static boolean setup(Configuration conf, JobConf jobConf,
                            final Arguments args)
      throws IOException {
    
    jobConf.set(OPERATION_LABEL, args.operation.getCmd());
    
    //encryption key or decryption key in credentials
    Credentials credentials = jobConf.getCredentials();
    
    if(args.encryptionKey != null)
      credentials.addSecretKey(new Text(ENCRYPTION_KEY_LABEL), writeKey(args.encryptionKey));
    
    if(args.decryptionKey != null)
      credentials.addSecretKey(new Text(DECRYPTION_KEY_LABEL), writeKey(args.decryptionKey));
    
    jobConf.setBoolean(Options.IGNORE_READ_FAILURES.propertyname,
        args.flags.contains(Options.IGNORE_READ_FAILURES));
    jobConf.setBoolean(Options.PRESERVE_STATUS.propertyname,
        args.flags.contains(Options.PRESERVE_STATUS));

    final String randomId = getRandomId();
    JobClient jClient = new JobClient(jobConf);
    Path stagingArea;
    try {
      stagingArea = JobSubmissionFiles.getStagingDir(jClient.getClusterHandle(), conf);
    } catch (InterruptedException e) {
      throw new IOException(e);
    }
    
    Path jobDirectory = new Path(stagingArea + NAME + "_" + randomId);
    FsPermission mapredSysPerms =
      new FsPermission(JobSubmissionFiles.JOB_DIR_PERMISSION);
   
    FileSystem.mkdirs(FileSystem.get(jobDirectory.toUri(),conf), jobDirectory, mapredSysPerms);
    jobConf.set(JOB_DIR_LABEL, jobDirectory.toString());

    long maxBytesPerMap = conf.getLong(BYTES_PER_MAP_LABEL, BYTES_PER_MAP);
    
    FileSystem dstfs = null;
    boolean dstExists = false;
    boolean dstIsDir = false;
    
    if(args.dst != null) {
      jobConf.set(DST_DIR_LABEL, args.dst.toUri().toString());
      
      dstfs = args.dst.getFileSystem(conf);
    
      // get tokens for all the required FileSystems..
      TokenCache.obtainTokensForNamenodes(jobConf.getCredentials(), 
                                        new Path[] {args.dst}, conf);
      
      dstExists = dstfs.exists(args.dst);
      if (dstExists) {
        dstIsDir = dstfs.getFileStatus(args.dst).isDirectory();
      }
    }

    // ouput path
    String filename = "_distcrypto_logs_" + randomId;
    Path logPath = args.log; 
    if (logPath == null) {
      if(args.dst == null)
        throw new IllegalArgumentException("logurl must be specified if dsturl is not specified.");
      
      if (!dstExists || !dstIsDir) {
        Path parent = args.dst.getParent();
        if (!dstfs.exists(parent)) {
          dstfs.mkdirs(parent);
        }
        logPath = new Path(parent, filename);
      } else {
        logPath = new Path(args.dst, filename);
      }
    } else {
      logPath = new Path(args.log, filename);
    }
    
    FileOutputFormat.setOutputPath(jobConf, logPath);

    // create src list, dst list
    FileSystem jobfs = jobDirectory.getFileSystem(jobConf);

    Path srcfilelist = new Path(jobDirectory, "_distcrypto_src_files");
    jobConf.set(SRC_LIST_LABEL, srcfilelist.toString());
    SequenceFile.Writer src_writer = SequenceFile.createWriter(jobfs, jobConf,
        srcfilelist, LongWritable.class, FilePair.class,
        SequenceFile.CompressionType.NONE);

    Path dstfilelist = new Path(jobDirectory, "_distcrypto_dst_files");
    SequenceFile.Writer dst_writer = SequenceFile.createWriter(jobfs, jobConf,
        dstfilelist, Text.class, Text.class,
        SequenceFile.CompressionType.NONE);

    Path dstdirlist = new Path(jobDirectory, "_distcrypto_dst_dirs");
    jobConf.set(DST_DIR_LIST_LABEL, dstdirlist.toString());
    SequenceFile.Writer dir_writer = SequenceFile.createWriter(jobfs, jobConf,
        dstdirlist, Text.class, FilePair.class,
        SequenceFile.CompressionType.NONE);

    // handle the case where the destination directory doesn't exist
    // and we've only a single src directory
    final boolean special = (args.srcs.size() == 1);
    int srcCount = 0, cnsyncf = 0, dirsyn = 0;
    long fileCount = 0L, byteCount = 0L, cbsyncs = 0L;
    int skipCount = 0;
    
    try {
      for(Iterator<SrcItem> srcItr = args.srcs.iterator(); srcItr.hasNext(); ) {
        final SrcItem src = srcItr.next();
        final Path srcPath = src.getPath();
        final SrcOptions srcOptions = src.getOptions();
        
        try {
          srcOptions.validate(jobConf);
        } catch(Exception e) {
          throw new IOException(e);
        }
        
        FileSystem srcfs = srcPath.getFileSystem(conf);
        FileStatus srcfilestat = srcfs.getFileStatus(srcPath);
        Path root = special && srcfilestat.isDir() ? 
            srcPath: srcPath.getParent();
        
        if (srcfilestat.isDir()) {
          ++srcCount;
        }

        Stack<FileStatus> pathstack = new Stack<FileStatus>();
        for(pathstack.push(srcfilestat); !pathstack.empty(); ) {
          FileStatus cur = pathstack.pop();
          FileStatus[] children = srcfs.listStatus(cur.getPath());
          for(int i = 0; i < children.length; i++) {
            boolean skipfile = false;
            final FileStatus child = children[i]; 
            final String relativesrc = makeRelative(root, child.getPath());
            final String relativedst = renameOutput(relativesrc, srcOptions);
            
            ++srcCount;

            if (child.isDir()) {
              pathstack.push(child);
            } else {
              
              String name = child.getPath().getName();
              if(!srcOptions.isMatch(name))
                skipfile = true;
              
              if (!skipfile) {
                ++fileCount;
                byteCount += child.getLen();

                if (LOG.isTraceEnabled()) {
                  LOG.trace("adding file " + child.getPath());
                }

                ++cnsyncf;
                cbsyncs += child.getLen();
                if (cnsyncf > SYNC_FILE_MAX || cbsyncs > maxBytesPerMap) {
                  src_writer.sync();
                  dst_writer.sync();
                  cnsyncf = 0;
                  cbsyncs = 0L;
                }
              } else {
                skipCount++;
              }
            } //if child.isDir

            if (!skipfile) {
              src_writer.append(new LongWritable(child.isDir()? 0: child.getLen()),
                  new FilePair(child, relativedst, srcOptions));
              
              dst_writer.append(new Text(relativedst),
                  new Text(child.getPath().toString()));
            }
            
          } //for child

          if (cur.isDir()) {
            String dst = makeRelative(root, cur.getPath());
            dir_writer.append(new Text(dst), new FilePair(cur, dst, srcOptions));
            if (++dirsyn > SYNC_FILE_MAX) {
              dirsyn = 0;
              dir_writer.sync();                
            }
          }
          
        } //for stack
      } //for src list
    } finally {
      checkAndClose(src_writer);
      checkAndClose(dst_writer);
      checkAndClose(dir_writer);
    }

    if(args.dst != null) {
      // create dst dir if needed
      
      FileStatus dststatus = null;
      try {
        dststatus = dstfs.getFileStatus(args.dst);
      } catch(FileNotFoundException fnfe) {
        LOG.info(args.dst + " does not exist.");
      }
      
      if (dststatus == null) {
        if (srcCount > 1 && !dstfs.mkdirs(args.dst)) {
          throw new IOException("Failed to create" + args.dst);
        }
      }
      
      Path tmpDir = new Path(
          (dstExists && !dstIsDir) || (!dstExists && srcCount == 1) ?
          args.dst.getParent(): args.dst, "_distcrypto_tmp_" + randomId);
      jobConf.set(TMP_DIR_LABEL, tmpDir.toUri().toString());
    }
    
    LOG.info("Total Folders and Files: " + srcCount);
    LOG.info("Skip Files: " + skipCount);
    LOG.info("Input Files: " + fileCount);
    LOG.info("Input Bytes: " + TraditionalBinaryPrefix.long2String(byteCount, "", 1));
    
    jobConf.setInt(SRC_COUNT_LABEL, srcCount);
    jobConf.setLong(TOTAL_SIZE_LABEL, byteCount);
    
    setMapCount(byteCount, jobConf);
    return fileCount > 0;
  }
  
  static String renameOutput(String relativeSrc, SrcOptions srcOptions) {
      Path src = new Path(relativeSrc);
      Path parent = src.getParent();
      String name = src.getName();
      
      boolean changed = false;
      String stripSuffix = srcOptions.getStripSuffix();
      if(stripSuffix != null && 
          !stripSuffix.isEmpty() &&
          name.endsWith(stripSuffix)) {
        name = name.substring(0, name.length() - stripSuffix.length());
        changed = true;
      }
      
      
      String appendSuffix = srcOptions.getAppendSuffix();
      if(appendSuffix != null &&
          !appendSuffix.isEmpty()) {
        name += appendSuffix;
        changed = true;
      }
      
      if(!changed)
        return relativeSrc;
      
      Path newPath = new Path(parent, name);
      return newPath.toString();
      
  }

  static boolean checkAndClose(java.io.Closeable io) {
    if (io != null) {
      try {
        io.close();
      }
      catch(IOException ioe) {
        LOG.warn(StringUtils.stringifyException(ioe));
        return false;
      }
    }
    return true;
  }
  
  public static Key parseKey(String hex) {
    if(hex == null)
      return null;
    
    hex = hex.toLowerCase();
    byte[] bytes = StringUtils.hexStringToByte(hex);
    
    int cryptographicLength = 256;
    if(bytes.length == 16)
      cryptographicLength = 128;
    else if(bytes.length == 32)
      cryptographicLength = 256;
    else
      return null; //invalid key length
      
    return new Key(Key.KeyType.SYMMETRIC_KEY, Key.AES, cryptographicLength, bytes);
  }
  
  public static Key readKey(byte[] input) throws IOException {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
    DataInputStream in = new DataInputStream(inputStream);
    
    Key key = new Key();
    key.readFields(in);
    
    return key;
  }
  
  public static byte[] writeKey(Key key) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    DataOutputStream out = new DataOutputStream(outputStream);
    
    key.write(out);
    out.flush();
    
    return outputStream.toByteArray();
  }
  
  /**
   * InputFormat of a distcrypto job responsible for generating splits of the src
   * file list.
   */
  static class CryptoInputFormat implements InputFormat<Text, Text> {

    /**
     * Produce splits such that each is no greater than the quotient of the
     * total size and the number of splits requested.
     * @param job The handle to the JobConf object
     * @param numSplits Number of splits requested
     */
    @SuppressWarnings("deprecation")
    public InputSplit[] getSplits(JobConf job, int numSplits)
        throws IOException {
      int cnfiles = job.getInt(SRC_COUNT_LABEL, -1);
      long cbsize = job.getLong(TOTAL_SIZE_LABEL, -1);
      String srcfilelist = job.get(SRC_LIST_LABEL, "");
      if (cnfiles < 0 || cbsize < 0 || "".equals(srcfilelist)) {
        throw new RuntimeException("Invalid metadata: #files(" + cnfiles +
                                   ") total_size(" + cbsize + ") listuri(" +
                                   srcfilelist + ")");
      }
      Path src = new Path(srcfilelist);
      FileSystem fs = src.getFileSystem(job);
      FileStatus srcst = fs.getFileStatus(src);

      ArrayList<FileSplit> splits = new ArrayList<FileSplit>(numSplits);
      LongWritable key = new LongWritable();
      FilePair value = new FilePair();
      final long targetsize = cbsize / numSplits;
      long pos = 0L;
      long last = 0L;
      long acc = 0L;
      long cbrem = srcst.getLen();
      SequenceFile.Reader sl = null;
      try {
        sl = new SequenceFile.Reader(fs, src, job);
        for (; sl.next(key, value); last = sl.getPosition()) {
          // if adding this split would put this split past the target size,
          // cut the last split and put this next file in the next split.
          if (acc + key.get() > targetsize && acc != 0) {
            long splitsize = last - pos;
            splits.add(new FileSplit(src, pos, splitsize, (String[])null));
            cbrem -= splitsize;
            pos = last;
            acc = 0L;
          }
          acc += key.get();
        }
      }
      finally {
        checkAndClose(sl);
      }
      if (cbrem != 0) {
        splits.add(new FileSplit(src, pos, cbrem, (String[])null));
      }

      return splits.toArray(new FileSplit[splits.size()]);
    }

    /**
     * Returns a reader for this split of the src file list.
     */
    public RecordReader<Text, Text> getRecordReader(InputSplit split,
        JobConf job, Reporter reporter) throws IOException {
      return new SequenceFileRecordReader<Text, Text>(job, (FileSplit)split);
    }
  }
  
  static class ProgressReporter implements CryptoProgressReporter {
    private Reporter reporter;
    private Path src;
    private Path dst;
    
    public ProgressReporter(Reporter reporter, Path src, Path dst) {
      this.reporter = reporter;
      this.src = src;
      this.dst = dst;
    }
    
    @Override
    public void reportProgress(String progress) {
      reporter.setStatus(progress + " " + src + " -> " + dst); 
    }
    
    @Override
    public Reporter getReporter() {
      return reporter;
    }
  }

  /**
   * CryptoFilesMapper: The mapper for encrypt, decrypt or rotate files.
   */
  static class CryptoFilesMapper
      implements Mapper<LongWritable, FilePair, WritableComparable<?>, Text> {
    // config
    private Operation operation = null;
    private Key encryptionKey = null;
    private Key decryptionKey = null;
    
    private boolean ignoreReadFailures;
    private EnumSet<FileAttribute> preserved = null;
    private Path dstDir = null;
    private FileSystem dstFs = null;
    private JobConf job;

    // stats
    private int failcount = 0;
    private int skipcount = 0;
    private int processedcount = 0;
    
    /** Mapper configuration.
     * Extracts source and destination file system, as well as
     * top-level paths on source and destination directories.
     * Gets the named file systems, to be used later in map.
     */
    public void configure(JobConf job)
    {
      String op = job.get(OPERATION_LABEL);
      
      try {
        operation = Operation.parseOperation(op);
      } catch(IllegalArgumentException e) {
        throw new RuntimeException("Invalid operation specified.", e);
      }
      
      Credentials credentials = job.getCredentials();
      
      byte[] encryptionKeyData = credentials.getSecretKey(new Text(ENCRYPTION_KEY_LABEL));
      if(encryptionKeyData != null) {
        try {
          encryptionKey = readKey(encryptionKeyData);
        } catch(IOException e) {
          throw new RuntimeException("Invalid encryption key specified.", e);
        }
      }
      
      byte[] decryptionKeyData = credentials.getSecretKey(new Text(DECRYPTION_KEY_LABEL));
      if(decryptionKeyData != null) {
        try {
          decryptionKey = readKey(decryptionKeyData);
        } catch(IOException e) {
          throw new RuntimeException("Invalid decryption key specified.", e);
        }
      }
      
      String dst = job.get(DST_DIR_LABEL);
      if(dst != null)
        dstDir = new Path(dst);
      
      if(dstDir != null) {
        try {
          dstFs = dstDir.getFileSystem(job);
        } catch (IOException ex) {
          throw new RuntimeException("Unable to get the named file system.", ex);
        }
      }
      
      ignoreReadFailures = job.getBoolean(Options.IGNORE_READ_FAILURES.propertyname, false);
      boolean preserve_status = job.getBoolean(Options.PRESERVE_STATUS.propertyname, false);
      if (preserve_status) {
        preserved = FileAttribute.parse(job.get(PRESERVE_STATUS_LABEL));
      } else {
        preserved = null;
      }
      
      this.job = job;
    }
    
    /** Map method. Copies one file from source file system to destination.
     * @param key src len
     * @param value FilePair (FileStatus src, Path dst)
     * @param out Log of failed copies
     * @param reporter
     */
    public void map(LongWritable key,
                    FilePair value,
                    OutputCollector<WritableComparable<?>, Text> out,
                    Reporter reporter) throws IOException {
      final FileStatus srcstat = value.input;
      final Path relativedst = new Path(value.output);
      try {
        crypto(srcstat, relativedst, value.options, out, reporter);
      } catch (IOException e) {
        ++failcount;
        
        reporter.incrCounter(CryptoCounter.FAIL_FILES, 1);
        updateStatus(reporter);
        
        final String sfailure = "FAIL " + relativedst + " : " +
                          StringUtils.stringifyException(e);
        out.collect(null, new Text(sfailure));
        
        LOG.info(sfailure);
        
      } finally {
        updateStatus(reporter);
      }
    }

    public void close() throws IOException {
      if (0 == failcount || ignoreReadFailures) {
        return;
      }
      throw new IOException(getCountString());
    }

    private String getCountString() {
      return "Processed: " + processedcount + " Skipped: " + skipcount
          + " Failed: " + failcount;
    }
    
    private void updateStatus(Reporter reporter) {
      reporter.setStatus(getCountString());
    }

    /**
     * Encrypt, decrypt or rotate a file to a destination.
     * @param srcstat src path and metadata
     * @param dstpath dst path
     * @param reporter
     */
    private void crypto(FileStatus srcstat, Path relativedst, SrcOptions srcOptions,
        OutputCollector<WritableComparable<?>, Text> outc, Reporter reporter)
        throws IOException {
      
      if (srcstat.isDirectory()) {
        //handling directory
        if(dstDir != null) {
          // if a directory, ensure created if dst dir specified
          Path dstpath = new Path(dstDir, relativedst);
          
          if (dstFs.exists(dstpath)) {
            if (!dstFs.getFileStatus(dstpath).isDirectory()) {
              throw new IOException("Failed to mkdirs: " + dstpath+" is a file.");
            }
          }
          else if (!dstFs.mkdirs(dstpath)) {
            throw new IOException("Failed to mkdirs " + dstpath);
          }
        }
        
        // TODO: when modification times can be set, directories should be
        // emitted to reducers so they might be preserved. Also, mkdirs does
        // not currently return an error when the directory already exists;
        // if this changes, all directory work might as well be done in reduce
        return;
      }
      
      //handling files
      Path srcpath = srcstat.getPath();
      Path srcdir = srcpath.getParent();
      
      //prepare dst path and file system
      Path dstpath = null;
      FileSystem dstfs = null;
      if(dstDir != null) {
        dstpath = new Path(dstDir, relativedst);
        dstfs = dstFs;
      } else {
        dstpath = new Path(srcdir, relativedst);
      
        try {
          dstfs = dstpath.getFileSystem(job);
        } catch (IOException ex) {
          throw new RuntimeException("Unable to get the named file system.", ex);
        }
      }
    
      int totfiles = job.getInt(SRC_COUNT_LABEL, -1);
      if (totfiles == 1) {
        // a single file; use dst dir provided by user as destination
        // rather than destination directory, if a file
        Path dstparent = dstpath.getParent();
        if (!(dstfs.exists(dstparent) &&
            dstfs.getFileStatus(dstparent).isDirectory())) {
          dstpath = dstparent;
        }
      }
      
      //temp file
      Path tmpfile = null;
      
      String tmpdir = job.get(TMP_DIR_LABEL);
      if(tmpdir != null)
        tmpfile = new Path(tmpdir, relativedst);
      else
        tmpfile = new Path(srcdir, "_tmp_file_" + getRandomId() + "_" + srcpath.getName());
      
      long processedBytes = 0L;
      
      CryptoProgressReporter progressReporter = 
          new ProgressReporter(reporter, srcpath, dstpath);
      
      try {
        //processing
        
        if(srcOptions.isRawFormat()) {
          processedBytes = cryptoRawFile(srcstat, tmpfile, dstfs, progressReporter);
        } else if(srcOptions.isSequenceFormat()) {
          processedBytes = cryptoSequenceFile(srcstat, tmpfile, dstfs, progressReporter);
        } else {
          //user defined file structure
          processedBytes = cryptoUserDefinedFile(srcOptions, srcstat, tmpfile, dstfs, progressReporter);
        }     
        
        //renaming
        if (dstfs.exists(dstpath) &&
            dstfs.getFileStatus(dstpath).isDirectory()) {
          throw new IOException(dstpath + " is a directory");
        }
        
        if (!dstfs.mkdirs(dstpath.getParent())) {
          throw new IOException("Failed to create parent dir: " + dstpath.getParent());
        }
        
        rename(dstfs, tmpfile, dstpath);
  
        //update status
        FileStatus dststat = dstfs.getFileStatus(dstpath);
        updatePermissions(dstfs, srcstat, dststat);
      } catch(IOException e) {
        //for any exception happened, remove the tmp file
        try {
          for (int i = 0; i < 3; ++i) {
            try {
              if (dstfs.delete(tmpfile, true))
                break;
            } catch (Throwable ex) {
              // ignore, we are just cleaning up
              LOG.debug("Ignoring cleanup exception", ex);
            }
            // update status, so we don't get timed out
            updateStatus(reporter);
            Thread.sleep(3 * 1000);
          }
        } catch (InterruptedException inte) {
          throw (IOException)new IOException().initCause(inte);
        }
        
        throw e;
      }

      // report at least once for each file
      ++processedcount;
      
      reporter.incrCounter(CryptoCounter.PROCESSED_FILES, 1);
      reporter.incrCounter(CryptoCounter.PROCESSED_BYTES, processedBytes);
      
      
      updateStatus(reporter);
    }
    
    private long cryptoRawFile(FileStatus src, Path dst, FileSystem dstfs, CryptoProgressReporter progressReporter) throws IOException {
      CryptoHandler cryptoHandler = new RawCryptoHandler();
      return cryptoFile(src, dst, dstfs, cryptoHandler, progressReporter);
    }
    
    private long cryptoSequenceFile(FileStatus src, Path dst, FileSystem dstfs, CryptoProgressReporter progressReporter) throws IOException {
      CryptoHandler cryptoHandler = new SequenceCryptoHandler();
      return cryptoFile(src, dst, dstfs, cryptoHandler, progressReporter);
    }
    
    private long cryptoUserDefinedFile(SrcOptions options, FileStatus src, Path dst, FileSystem dstfs, CryptoProgressReporter progressReporter) throws IOException {
      String formatClassName = options.getFormat();
      CryptoHandler cryptoHandler = null;
      try {
        @SuppressWarnings("unchecked")
        Class<CryptoHandler> clz = (Class<CryptoHandler>)job.getClassByName(formatClassName);
        
        cryptoHandler = ReflectionUtils.newInstance(clz, job);
      } catch(ClassNotFoundException e) {
        throw new IOException(e);
      }
      
      return cryptoFile(src, dst, dstfs, cryptoHandler, progressReporter);
    }
    
    private long cryptoFile(FileStatus src, Path dst, FileSystem dstfs,
        CryptoHandler cryptoHandler, CryptoProgressReporter progressReporter) throws IOException {
      
      cryptoHandler.configure(job, preserved);
      
      switch(operation) {
      case ENCRYPT: {
        return cryptoHandler.encryptFile( encryptionKey, 
            src, dst, dstfs, progressReporter);
      }
      case DECRYPT: {
        return cryptoHandler.decryptFile(decryptionKey, 
            src, dst, dstfs, progressReporter);
      }
      case ROTATE: {
        return cryptoHandler.rotateFile(decryptionKey, encryptionKey,
            src, dst, dstfs, progressReporter);
      }
      default:
        return 0;
      }
    }
    
    /** rename tmp to dst, delete dst if already exists */
    private void rename(FileSystem fs, Path tmp, Path dst) throws IOException {
      try {
        if (fs.exists(dst)) {
          fs.delete(dst, true);
        }
        if (!fs.rename(tmp, dst)) {
          throw new IOException();
        }
      }
      catch(IOException cause) {
        throw (IOException)new IOException("Fail to rename tmp file (=" + tmp 
            + ") to destination file (=" + dst + ")").initCause(cause);
      }
    }

    private void updatePermissions(FileSystem fs, FileStatus src, FileStatus dst
        ) throws IOException {
      if (preserved != null) {
        DistCrypto.updatePermissions(src, dst, preserved, fs);
      }
    }

    static String bytesString(long b) {
      return b + " bytes (" + TraditionalBinaryPrefix.long2String(b, "", 1) + ")";
    }
  }
  
  private static class RawCryptoHandler implements CryptoHandler {
    private int bufferSize = 128 * 1024;
    private JobConf job = null;
    private EnumSet<FileAttribute> preserved = null;
    
    @Override
    public void configure(JobConf job, EnumSet<FileAttribute> preserved) {
      this.job = job;
      this.preserved = preserved;
      
      bufferSize = job.getInt("crypto.buf.size", 128 * 1024);
    }

    @Override
    public long encryptFile(Key encryptionKey, FileStatus src,
        Path dst, FileSystem dstfs, CryptoProgressReporter reporter)
        throws IOException {
      return encryptRawFile(encryptionKey, src, dst, dstfs, reporter);
    }

    @Override
    public long decryptFile(Key decryptionKey, FileStatus src,
        Path dst, FileSystem dstfs, CryptoProgressReporter reporter)
        throws IOException {
      return decryptRawFile(decryptionKey, src, dst, dstfs, reporter);
    }

    @Override
    public long rotateFile(Key decryptionKey, Key encryptionKey,
        FileStatus src, Path dst, FileSystem dstfs,
        CryptoProgressReporter reporter) throws IOException {
      return rotateRawFile(decryptionKey, encryptionKey, src, dst, dstfs, reporter);
    }
    
    private void reportProgress(CryptoProgressReporter reporter, long cbprocessed, long cbtotal) {
      reporter.reportProgress(
          String.format("%.2f %%", cbprocessed*100.0/cbtotal) +
          " [ " + TraditionalBinaryPrefix.long2String(cbprocessed, "", 1) + " / " +
          TraditionalBinaryPrefix.long2String(cbtotal, "", 1) + " ]");
    }

    @SuppressWarnings("deprecation")
    private FSDataOutputStream create(FileSystem fs, Path f, Reporter reporter,
        FileStatus srcstat) throws IOException {
      if (fs.exists(f)) {
        fs.delete(f, false);
      }
      
      if (preserved == null) {
        return fs.create(f, true, bufferSize, reporter);
      } else {
        //preserve status
        FsPermission permission = preserved.contains(FileAttribute.PERMISSION)?
            srcstat.getPermission(): null;
        short replication = preserved.contains(FileAttribute.REPLICATION)?
            srcstat.getReplication(): fs.getDefaultReplication();
        long blockSize = preserved.contains(FileAttribute.BLOCK_SIZE)?
            srcstat.getBlockSize(): fs.getDefaultBlockSize();
        return fs.create(f, permission, true, bufferSize, replication,
            blockSize, reporter);
      }
    }
    
    private long encryptRawFile(Key encryptionKey,
        FileStatus src, Path dst, FileSystem dstfs, CryptoProgressReporter reporter) throws IOException {
      final Path srcpath = src.getPath();
      final long cbsrc = src.getLen();
      long cbprocessed = 0L;

      FSDataInputStream dataIn = null;
      FSDataOutputStream dataOut = null;
      try {
        // open src file
        dataIn = srcpath.getFileSystem(job).open(srcpath);

        // open tmp file
        dataOut = create(dstfs, dst, reporter.getReporter(), src);

        OutputStream out = null;

        AESCodec encryptCodec = new AESCodec();
        encryptCodec.setConf(job);

        CryptoContext encryptContext = new CryptoContext();
        encryptContext.setKey(encryptionKey);
        encryptCodec.setCryptoContext(encryptContext);

        out = encryptCodec.createOutputStream(dataOut);

        try {
          byte[] buffer = new byte[bufferSize];

          // process the file
          for(int cbread; (cbread = dataIn.read(buffer)) >= 0; ) {
            out.write(buffer, 0, cbread);

            cbprocessed = dataIn.getPos();
            reportProgress(reporter, cbprocessed, cbsrc);
          }
        } finally {
          if(checkAndClose(out))
            dataOut = null;
        }
      } finally {
        checkAndClose(dataIn);
        checkAndClose(dataOut);
      }

      return cbprocessed;
    }

    private long decryptRawFile(Key decryptionKey,
        FileStatus src, Path dst, FileSystem dstfs, CryptoProgressReporter reporter) throws IOException {
      final Path srcpath = src.getPath();
      final long cbsrc = src.getLen();
      long cbprocessed = 0L;

      FSDataInputStream dataIn = null;
      FSDataOutputStream dataOut = null;
      try {
        // open src file
        dataIn = srcpath.getFileSystem(job).open(srcpath);

        // open tmp file
        dataOut = create(dstfs, dst, reporter.getReporter(), src);

        InputStream in = null;

        AESCodec decryptCodec = new AESCodec();
        decryptCodec.setConf(job);

        CryptoContext decryptContext = new CryptoContext();
        decryptContext.setKey(decryptionKey);
        decryptCodec.setCryptoContext(decryptContext);

        in = decryptCodec.createInputStream(dataIn);

        try {
          byte[] buffer = new byte[bufferSize];

          // process the file
          for(int cbread; (cbread = in.read(buffer)) >= 0; ) {
            dataOut.write(buffer, 0, cbread);

            cbprocessed = dataIn.getPos();
            reportProgress(reporter, cbprocessed, cbsrc);
          }
        } finally {
          if(checkAndClose(in))
            dataIn = null;
        }
      } finally {
        checkAndClose(dataIn);
        checkAndClose(dataOut);
      }

      return cbprocessed;
    }

    private long rotateRawFile(Key decryptionKey, Key encryptionKey,
        FileStatus src, Path dst, FileSystem dstfs, 
        CryptoProgressReporter reporter) throws IOException {
      final Path srcpath = src.getPath();
      final long cbsrc = src.getLen();
      long cbprocessed = 0L;

      FSDataInputStream dataIn = null;
      FSDataOutputStream dataOut = null;
      try {
        // open src file
        dataIn = srcpath.getFileSystem(job).open(srcpath);

        // open tmp file
        dataOut = create(dstfs, dst, reporter.getReporter(), src);

        InputStream in = null;
        OutputStream out = null;

        AESCodec decryptCodec = new AESCodec();
        decryptCodec.setConf(job);

        CryptoContext decryptContext = new CryptoContext();
        decryptContext.setKey(decryptionKey);
        decryptCodec.setCryptoContext(decryptContext);

        in = decryptCodec.createInputStream(dataIn);

        AESCodec encryptCodec = new AESCodec();
        encryptCodec.setConf(job);

        CryptoContext encryptContext = new CryptoContext();
        encryptContext.setKey(encryptionKey);
        encryptCodec.setCryptoContext(encryptContext);

        out = encryptCodec.createOutputStream(dataOut);

        try {
          byte[] buffer = new byte[bufferSize];

          // process the file
          for(int cbread; (cbread = in.read(buffer)) >= 0; ) {
            out.write(buffer, 0, cbread);

            cbprocessed = dataIn.getPos();
            reportProgress(reporter, cbprocessed, cbsrc);
          }
        } finally {
          if(checkAndClose(in))
            dataIn = null;

          if(checkAndClose(out))
            dataOut = null;
        }
      } finally {
        checkAndClose(dataIn);
        checkAndClose(dataOut);
      }

      return cbprocessed;
    }
  }
  
  public static class SequenceFileAsBinary extends SequenceFileAsBinaryOutputFormat {
    public static final String OUTPUT_FILE = "mapreduce.output.distcrypto.file";
    private int bufferSize;
    private short replication; 
    private long blockSize;
    
    public SequenceFileAsBinary(int bufferSize, short replication, long blockSize) {
      this.bufferSize = bufferSize;
      this.replication = replication;
      this.blockSize = blockSize;
    }
    
    public Path getDefaultWorkFile(TaskAttemptContext context,
        String extension) throws IOException{
      String file = context.getConfiguration().get(OUTPUT_FILE);
      return new Path(file);
    }
    
    @SuppressWarnings("deprecation")
    protected SequenceFile.Writer getSequenceWriter(TaskAttemptContext context,
        Class<?> keyClass, Class<?> valueClass)
        throws IOException {
      Configuration conf = context.getConfiguration();

      CompressionCodec codec = null;
      CompressionType compressionType = CompressionType.NONE;
      if (getCompressOutput(context)) {
        // find the kind of compression to do
        compressionType = getOutputCompressionType(context);
        // find the right codec
        Class<?> codecClass = getOutputCompressorClass(context,
                                                       DefaultCodec.class);
        codec = (CompressionCodec)
          ReflectionUtils.newInstance(codecClass, conf);
      }
      // get the path of the temporary output file
      Path file = getDefaultWorkFile(context, "");
      
      if(codec != null &&
          codec instanceof CryptoCodec &&
          conf instanceof JobConf)
        CryptoContextHelper.resetOutputCryptoContext((CryptoCodec) codec, (JobConf)conf, file);
      
      FileSystem fs = file.getFileSystem(conf);
      return SequenceFile.createWriter(fs, conf, file,
          keyClass,
          valueClass,
          bufferSize,
          replication,
          blockSize,
          compressionType,
          codec,
          context,
          new Metadata());
      }
  }
  
  private static class SequenceCryptoHandler implements CryptoHandler {
    private JobConf job = null;
    private EnumSet<FileAttribute> preserved = null;
    
    private int bufferSize = 128 * 1024;
    
    @Override
    public void configure(JobConf job, EnumSet<FileAttribute> preserved) {
      this.job = job;
      this.preserved = preserved;
      
      bufferSize = job.getInt("crypto.buf.size", 128 * 1024);
    }
    
    @Override
    public long encryptFile(Key encryptionKey, FileStatus src,
        Path dst, FileSystem dstfs, CryptoProgressReporter reporter)
        throws IOException {
      Job workingJob = Job.getInstance(job);
      JobConf jobConf = (JobConf)workingJob.getConfiguration();
      
      //set output codec class
      org.apache.hadoop.mapred.FileOutputFormat.setOutputCompressorClass(jobConf, AESCodec.class);
      org.apache.hadoop.mapred.SequenceFileOutputFormat.setOutputCompressionType(jobConf, CompressionType.BLOCK);

      try { 
        //set output key provider
        FileMatches fileMatches = new FileMatches(KeyContext.fromKey(encryptionKey));
        FileMatchCryptoContextProvider.setOutputCryptoContextProvider(jobConf, fileMatches, null);
      } catch(CryptoException e) {
        throw new IOException(e);
      }
      
      return cryptoSequenceFile(workingJob, src, dst, dstfs, reporter);
    }

    @Override
    public long decryptFile(Key decryptionKey, FileStatus src,
        Path dst, FileSystem dstfs, CryptoProgressReporter reporter)
        throws IOException {
      Job workingJob = Job.getInstance(job);
      JobConf jobConf = (JobConf)workingJob.getConfiguration();
      
      try { 
        //set input key provider
        FileMatches fileMatches = new FileMatches(KeyContext.fromKey(decryptionKey));
        FileMatchCryptoContextProvider.setInputCryptoContextProvider(jobConf, fileMatches, null);
      } catch(CryptoException e) {
        throw new IOException(e);
      }
      
      return cryptoSequenceFile(workingJob, src, dst, dstfs, reporter);
    }

    @Override
    public long rotateFile(Key decryptionKey, Key encryptionKey,
        FileStatus src, Path dst, FileSystem dstfs,
        CryptoProgressReporter reporter) throws IOException {
      Job workingJob = Job.getInstance(job);
      JobConf jobConf = (JobConf)workingJob.getConfiguration();
      
      try { 
        //set input key provider
        FileMatches fileMatches = new FileMatches(KeyContext.fromKey(decryptionKey));
        FileMatchCryptoContextProvider.setInputCryptoContextProvider(jobConf, fileMatches, null);
      } catch(CryptoException e) {
        throw new IOException(e);
      }
      
      //set output codec class
      org.apache.hadoop.mapred.FileOutputFormat.setOutputCompressorClass(jobConf, AESCodec.class);
      org.apache.hadoop.mapred.SequenceFileOutputFormat.setOutputCompressionType(jobConf, CompressionType.BLOCK);

      try { 
        //set output key provider
        FileMatches fileMatches = new FileMatches(KeyContext.fromKey(encryptionKey));
        FileMatchCryptoContextProvider.setOutputCryptoContextProvider(jobConf, fileMatches, null);
      } catch(CryptoException e) {
        throw new IOException(e);
      }
      
      return cryptoSequenceFile(workingJob, src, dst, dstfs, reporter);
    }
    
    public static TaskAttemptContext createDummyMapTaskAttemptContext(
        Configuration conf) {
      TaskAttemptID tid = new TaskAttemptID("jt", 1, TaskType.MAP, 0, 0);
      conf.set("mapred.task.id", tid.toString());
      return new TaskAttemptContextImpl(conf, tid);    
    }

    public static StatusReporter createDummyReporter() {
      return new StatusReporter() {
        public void setStatus(String s) {
        }
        
        public void progress() {
        }

				public float getProgress(){
					return 0;
				}
        
        public Counter getCounter(Enum<?> name) {
          return new Counters().findCounter(name);
        }
        
        public Counter getCounter(String group, String name) {
          return new Counters().findCounter(group, name);
        }
      };
    }
    
    @SuppressWarnings("deprecation")
    private long cryptoSequenceFile(Job job, FileStatus src, Path dst, FileSystem dstfs, CryptoProgressReporter reporter) throws IOException {
      final Path srcpath = src.getPath();
      final long cbsrc = src.getLen();
      
      JobConf jobConf = (JobConf)job.getConfiguration();
      
      TaskAttemptContext context = createDummyMapTaskAttemptContext(jobConf);
      org.apache.hadoop.mapreduce.InputFormat<BytesWritable,BytesWritable> iformat =
          new SequenceFileAsBinaryInputFormat();
      
      //preserve status
      short replication = preserved !=null && preserved.contains(FileAttribute.REPLICATION)?
          src.getReplication(): dstfs.getDefaultReplication();
      long blockSize = preserved !=null && preserved.contains(FileAttribute.BLOCK_SIZE)?
          src.getBlockSize(): dstfs.getDefaultBlockSize();
          
      org.apache.hadoop.mapreduce.OutputFormat<BytesWritable,BytesWritable> oformat =
          new SequenceFileAsBinary(bufferSize, replication, blockSize);

      FileInputFormat.setInputPaths(job, srcpath.toString());
      
      org.apache.hadoop.mapreduce.RecordWriter<BytesWritable, BytesWritable> writer = null;
      
      int count = 0;
      try {
        for (org.apache.hadoop.mapreduce.InputSplit split : iformat.getSplits(job)) {
          SequenceFileAsBinaryRecordReader reader =
              (SequenceFileAsBinaryRecordReader)iformat.createRecordReader(split, context);
          MapContext<BytesWritable, BytesWritable, BytesWritable, BytesWritable> 
          mcontext = new MapContextImpl<BytesWritable, BytesWritable,
          BytesWritable, BytesWritable>(jobConf, 
              context.getTaskAttemptID(), reader, null, null, 
              createDummyReporter(), 
              split);
          reader.initialize(split, mcontext);
          
          if(writer == null) {
            String keyClassName = reader.getKeyClassName();
            String valueClassName = reader.getValueClassName();
            
            Configuration conf = context.getConfiguration();
            conf.set(SequenceFileAsBinary.OUTPUT_FILE, dst.toString());
            conf.set(SequenceFileAsBinary.KEY_CLASS, keyClassName);
            conf.set(SequenceFileAsBinary.VALUE_CLASS, valueClassName);
                
            writer = oformat.getRecordWriter(context);
          }
          try {
            while (reader.nextKeyValue()) {
              BytesWritable bkey = reader.getCurrentKey();
              BytesWritable bval = reader.getCurrentValue();

              writer.write(bkey, bval);

              ++count;
              
              if(count % 100 == 0) {
                reporter.reportProgress("[" + count + "] records processed." );
              }
            }
            
            reporter.reportProgress("[" + count + "] records processed.");
          } finally {
            reader.close();
          }
        }
      } catch(InterruptedException e) {
          throw new IOException(e);
      } finally {
        //close writer if needed
        if(writer != null) {
          try {
            writer.close(context);
          } catch(InterruptedException e) {
            throw new IOException(e);
          }
        }
      }
      
      return cbsrc;
    }
  }
}
