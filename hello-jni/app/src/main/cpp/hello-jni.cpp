/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <string.h>
#include <jni.h>

#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

#include <stdio.h>
#include <errno.h>

#include<android/log.h>

#define TAG "myDemo-jni" // 这个是自定义的LOG的标识
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG ,__VA_ARGS__) // 定义LOGI类型
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG ,__VA_ARGS__) // 定义LOGW类型
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGE类型
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL,TAG ,__VA_ARGS__) // 定义LOGF类型

extern int errno;

/* This is a trivial JNI example where we use a native method
 * to return a new VM String. See the corresponding Java source
 * file located at:
 *
 *   hello-jni/app/src/main/java/com/example/hellojni/HelloJni.java
 */
extern "C" {
JNIEXPORT jstring JNICALL
Java_com_example_hellojni_HelloJni_stringFromJNI(JNIEnv *env,
                                                 jobject thiz) {
#if defined(__arm__)
#if defined(__ARM_ARCH_7A__)
#if defined(__ARM_NEON__)
#if defined(__ARM_PCS_VFP)
#define ABI "armeabi-v7a/NEON (hard-float)"
#else
#define ABI "armeabi-v7a/NEON"
#endif
#else
#if defined(__ARM_PCS_VFP)
#define ABI "armeabi-v7a (hard-float)"
#else
#define ABI "armeabi-v7a"
#endif
#endif
#else
#define ABI "armeabi"
#endif
#elif defined(__i386__)
#define ABI "x86"
#elif defined(__x86_64__)
#define ABI "x86_64"
#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
#define ABI "mips64"
#elif defined(__mips__)
#define ABI "mips"
#elif defined(__aarch64__)
#define ABI "arm64-v8a"
#else
#define ABI "unknown"
#endif

    jstring ts_ret;
    char buffer[50];
    sprintf(buffer, "Everything is right %d", 12);

    int TempSocket = socket(PF_INET, SOCK_STREAM, 0);
    if (TempSocket) {
        struct ifreq IfReqs[8];
        struct ifconf IfConfig;

        memset(&IfConfig, 0, sizeof(IfConfig));
        IfConfig.ifc_ifcu.ifcu_req = IfReqs;
        IfConfig.ifc_len = sizeof(IfReqs);

        int Result = ioctl(TempSocket, SIOCGIFCONF, &IfConfig);
        if (Result == 0) {
            int32_t WifiAddress = 0;
            int32_t CellularAddress = 0;
            int32_t OtherAddress = 0;

            for (int32_t IdxReq = 0; IdxReq < 8; ++IdxReq) {
                // Examine interfaces that are up and not loop back
                int ResultFlags = ioctl(TempSocket, SIOCGIFFLAGS, &IfReqs[IdxReq]);
                if (ResultFlags == 0 &&
                    (IfReqs[IdxReq].ifr_flags & IFF_UP) &&
                    (IfReqs[IdxReq].ifr_flags & IFF_LOOPBACK) == 0) {
                    auto* tp_IfrAddr = &IfReqs[IdxReq].ifr_addr;
                    struct sockaddr_in* tp_SocAddr = reinterpret_cast<sockaddr_in *>(tp_IfrAddr);

                    if (strcmp(IfReqs[IdxReq].ifr_name, "wlan0") == 0) {
                        // 'Usually' wifi, Prefer wifi
                        WifiAddress = tp_SocAddr->sin_addr.s_addr;
                        break;
                    } else if (strcmp(IfReqs[IdxReq].ifr_name, "rmnet0") == 0) {
                        // 'Usually' cellular
                        CellularAddress = tp_SocAddr->sin_addr.s_addr;
                    } else if (OtherAddress == 0) {
                        // First alternate found
                        OtherAddress = tp_SocAddr->sin_addr.s_addr;
                    }
                }
            }

            // Prioritize results found
            if (WifiAddress != 0)
            {
                // Prefer Wifi
                sprintf(buffer, "Wifi IP: %d", WifiAddress);
            }
            else if (CellularAddress != 0)
            {
                // Then cellular
                sprintf(buffer, "Cellular IP %d", CellularAddress);
            }
            else if (OtherAddress != 0)
            {
                // Then whatever else was found
                sprintf(buffer, "OtherAddress IP %d", OtherAddress);
            }
            else
            {
                // Give up
                sprintf(buffer,"Get no valid ip");
            }

        } else {
            int ErrNo = errno;
            sprintf(buffer, "Ioctl error %d||%d||%s", Result, errno, strerror(ErrNo));
        }
    } else {
        sprintf(buffer, "Socket create failed");
    }

    close(TempSocket);
    ts_ret = env->NewStringUTF(buffer);
    return ts_ret;
}
}