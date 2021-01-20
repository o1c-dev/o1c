/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class dev_o1c_lib_O1CLib */

#ifndef _Included_dev_o1c_lib_O1CLib
#define _Included_dev_o1c_lib_O1CLib
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    randomBytes
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_randomBytes
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    entropyBytes
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_entropyBytes
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    hashStateSize
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_dev_o1c_lib_O1CLib_hashStateSize
  (JNIEnv *, jclass);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    hashInit
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_hashInit
  (JNIEnv *, jclass, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    keyedHashInit
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_keyedHashInit
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    kdfHashInit
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_kdfHashInit
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    hashUpdate
 * Signature: ([B[BII)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_hashUpdate
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    hashFinal
 * Signature: ([B[BI)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_hashFinal
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    hash
 * Signature: ([BII[BII)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_hash
  (JNIEnv *, jclass, jbyteArray, jint, jint, jbyteArray, jint, jint);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    keyedHash
 * Signature: ([B[BII[BII)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_keyedHash
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jbyteArray, jint, jint);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    scalarFieldBaseMultiply
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_scalarFieldBaseMultiply
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    scalarFieldMultiply
 * Signature: ([B[B[B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_scalarFieldMultiply
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    generateScalarFieldKeyPair
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_generateScalarFieldKeyPair
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    authenticatedEncrypt
 * Signature: ([B[B[B[BII[BI[BI)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_authenticatedEncrypt
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jint, jint, jbyteArray, jint, jbyteArray, jint);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    authenticatedDecrypt
 * Signature: ([B[B[B[BII[BI[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_dev_o1c_lib_O1CLib_authenticatedDecrypt
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray, jint, jint, jbyteArray, jint, jbyteArray, jint);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    deriveKeyPairFromSeed
 * Signature: ([B[B[B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_deriveKeyPairFromSeed
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    generateSignKeyPair
 * Signature: ([B[B)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_generateSignKeyPair
  (JNIEnv *, jclass, jbyteArray, jbyteArray);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    sign
 * Signature: ([B[BII[BI)V
 */
JNIEXPORT void JNICALL Java_dev_o1c_lib_O1CLib_sign
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     dev_o1c_lib_O1CLib
 * Method:    verify
 * Signature: ([B[BII[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_dev_o1c_lib_O1CLib_verify
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jint, jint, jbyteArray, jint);

#ifdef __cplusplus
}
#endif
#endif
