/*
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "config.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include "org_apache_hadoop.h"

#include "org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher.h"

#define ENCRYPTION 1
#define DECRYPTION 0

/*
 * Class:     sec_util_OpenSSLCrypto
  * mode: 0, ENCRYPTION, 1: DECRYPTION
 * return: context Id
 * Method:    init
 */
JNIEXPORT jlong JNICALL Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_init
    (JNIEnv * env, jobject object, jint mode, jbyteArray key, jbyteArray iv) {
  // Load libcrypto.so
	void *libcrypto = dlopen(HADOOP_CRYPTO_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
	if (!libcrypto) {
	  char msg[1000];
		snprintf(msg, 1000, "%s (%s)!", "Cannot load " HADOOP_CRYPTO_LIBRARY, dlerror());
		THROW(env, "java/lang/UnsatisfiedLinkError", msg);
		return 0;
	}

	// Locate the requisite symbols from libcrypto.so
	dlerror();

	EVP_CIPHER_CTX * context = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
  int keyLength = (*env)->GetArrayLength(env, key);
  int ivLength = (*env)->GetArrayLength(env, iv);

  jbyte * nativeKey = (jbyte*)malloc(keyLength);
  jbyte * nativeIv = (jbyte*)malloc(ivLength);

  (*env)->GetByteArrayRegion(env, key, 0, keyLength, nativeKey);
  (*env)->GetByteArrayRegion(env, iv, 0, ivLength, nativeIv);

  if (mode == ENCRYPTION) {
    EVP_CIPHER_CTX_init(context);
    if (keyLength == 32) {
      EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
    else if (keyLength == 16) {
      EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
  }
  else {
    EVP_CIPHER_CTX_init(context);
    if (keyLength == 32) {
      EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
    else if (keyLength == 16) {
      EVP_DecryptInit_ex(context, EVP_aes_128_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
  }

	free(nativeKey);
	free(nativeIv);
  return (long)context;
}

JNIEXPORT void JNICALL Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_reset
    (JNIEnv * env, jobject object, jlong context, jbyteArray key, jbyteArray iv) {
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)context;
  jbyte * nativeKey = NULL;
  jbyte * nativeIv = NULL;
  if (NULL != key) {
    nativeKey = (*env)->GetByteArrayElements(env, key, NULL);
  }

  if (NULL != iv) {
    nativeIv = (*env)->GetByteArrayElements(env, iv, NULL);
  }

  if (ctx->encrypt == ENCRYPTION) {
    //re-initialize existing ctx without new memory allocation
    //basically what it does is to reset the working IV.
    EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
  }
  else {
    EVP_DecryptInit_ex(ctx, NULL, NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
  }
    
  if (NULL != key) {
    (*env)->ReleaseByteArrayElements(env, key, nativeKey, 0);
  }

  if (NULL != iv) {
    (*env)->ReleaseByteArrayElements(env, iv, nativeIv, 0);
  }
}

JNIEXPORT void JNICALL Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_cleanup
    (JNIEnv * env, jobject object, jlong context) {
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)context;
  EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
}

/*
 * Class:     org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher
 * Method:    doFinal
 */
JNIEXPORT jint JNICALL Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_doFinal
    (JNIEnv * env, jobject object, jlong context, jobject inputDirectBuffer, jint inputLength, jobject outputDirectBuffer) {
  unsigned char * input = (unsigned char *)(*env)->GetDirectBufferAddress(env, inputDirectBuffer);
  unsigned char * output = (unsigned char *)(*env)->GetDirectBufferAddress(env, outputDirectBuffer);
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)context;

  int outLength = 0;
  int outLengthFinal = 0;
  if (ctx->encrypt == ENCRYPTION) {
    if(!EVP_EncryptUpdate(ctx, output, &outLength, input, inputLength)){
      printf("ERROR in EVP_EncryptUpdate \n");
      ERR_print_errors_fp(stderr);
      //Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_reset(env, object, context, NULL, NULL);
      return 0;
    }
    /* update ciphertext with the final remaining bytes */
    if(!EVP_EncryptFinal_ex(ctx, (unsigned char *)output + outLength, &outLengthFinal)){
      printf("ERROR in EVP_EncryptFinal_ex \n");
      ERR_print_errors_fp(stderr);
      //Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_reset(env, object, context, NULL, NULL);
      return 0;
    }
  }
  else {
    if(!EVP_DecryptUpdate(ctx,(unsigned char *)output, &outLength, (unsigned char *)input, inputLength)){
      printf("ERROR in EVP_DecryptUpdate\n");
      ERR_print_errors_fp(stderr);
      Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_reset(env, object, context, NULL, NULL);
      return 0;
    }

    if(!EVP_DecryptFinal_ex(ctx, (unsigned char *)output + outLength, &outLengthFinal)){
      printf("ERROR in EVP_DecryptFinal_ex\n");
      ERR_print_errors_fp(stderr);
      Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_reset(env, object, context, NULL, NULL);
      return 0;
    }
  }
  Java_org_apache_hadoop_io_crypto_aes_NativeOpensslAESCipher_reset(env, object, context, NULL, NULL);
  return outLength + outLengthFinal;
}
