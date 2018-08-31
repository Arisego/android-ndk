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


///////////////////////////////////////////////////////////////////////////////////////////////////
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

#include <string>
std::string ls_All;
char lc_buffer[50];

#define log_out(...) LOGW(__VA_ARGS__);    sprintf(lc_buffer,__VA_ARGS__);ls_All += lc_buffer;

#include <vector>
#include <ifaddrs.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <vector>
#include <string>
#include <iostream>
#include <netinet/in.h>
#include <net/if.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
#include <netdb.h>

void ipv6_to_str_unexpanded(char * str, const struct in6_addr * addr) {
    sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)addr->s6_addr[0], (int)addr->s6_addr[1],
            (int)addr->s6_addr[2], (int)addr->s6_addr[3],
            (int)addr->s6_addr[4], (int)addr->s6_addr[5],
            (int)addr->s6_addr[6], (int)addr->s6_addr[7],
            (int)addr->s6_addr[8], (int)addr->s6_addr[9],
            (int)addr->s6_addr[10], (int)addr->s6_addr[11],
            (int)addr->s6_addr[12], (int)addr->s6_addr[13],
            (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

void Resolve_RemoteAddr(int ai_Family, const char* name)
{
    struct addrinfo* addr_result;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = ai_Family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags |= AI_ADDRCONFIG;

    int result = getaddrinfo(name, nullptr, &hints, &addr_result);
    if(result == 0)
    {
        addrinfo* AddrInfoIndex = addr_result;

        for (; AddrInfoIndex != nullptr; AddrInfoIndex = AddrInfoIndex->ai_next)
        {
            if (AddrInfoIndex->ai_family == AF_INET)
            {
                sockaddr_in* IPv4SockAddr = reinterpret_cast<sockaddr_in*>(AddrInfoIndex->ai_addr);
                if (IPv4SockAddr != nullptr)
                {
                    log_out("\n - Ipv4: %s", inet_ntoa(IPv4SockAddr->sin_addr));
                }
            }

            if (AddrInfoIndex->ai_family == AF_INET6)
            {
                sockaddr_in6* IPv6SockAddr = reinterpret_cast<sockaddr_in6*>(AddrInfoIndex->ai_addr);
                if (IPv6SockAddr != nullptr)
                {
                    char addr6_Buf[120];
                    ipv6_to_str_unexpanded(addr6_Buf, &IPv6SockAddr->sin6_addr);
                    log_out("\n - Ipv6: %s", addr6_Buf);
                }
            }

        }

        freeaddrinfo(addr_result);
    } else{
        int ErrNo = errno;
        std::string ts_ErrInf = strerror(ErrNo);

        std::string ts_ResInf = "";
        switch(result)
        {
            case EAI_NODATA:
                ts_ResInf = "no address associated with hostname";
                break;
        }

        log_out("\n getaddrinfo failed\n - Return: %d||%s\n - Error: %d||%s", result, ts_ResInf.c_str(), errno, ts_ErrInf.c_str());
    }
}

void Resolve_Host(const char* name)
{
    log_out("\n Resolve_Host: %s", name);

    Resolve_RemoteAddr(AF_INET, name);
    Resolve_RemoteAddr(AF_INET6, name);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
#define IPV6_ADDR_GLOBAL 0x0000U
#define IPV6_ADDR_LOOPBACK 0x0010U
#define IPV6_ADDR_LINKLOCAL 0x0020U
#define IPV6_ADDR_SITELOCAL 0x0040U
#define IPV6_ADDR_COMPATv4 0x0080U

/* ifa_flags */
#define V6_IFA_F_SECONDARY		0x01
#define V6_IFA_F_TEMPORARY		IFA_F_SECONDARY

#define	V6_IFA_F_NODAD		0x02
#define V6_IFA_F_OPTIMISTIC	0x04
#define V6_IFA_F_DADFAILED		0x08
#define	V6_IFA_F_HOMEADDRESS	0x10
#define V6_IFA_F_DEPRECATED	0x20
#define V6_IFA_F_TENTATIVE		0x40
#define V6_IFA_F_PERMANENT		0x80

void parse_inet6()
{
    log_out("\n -- Try parse local inet6 by prof net file --");

    FILE*f;
    int ret,scope,prefix, ifa_flag;
    unsigned char ipv6[16];
    char dname[IFNAMSIZ];
    char address[INET6_ADDRSTRLEN];
    std::string scopestr;

    f=fopen("/proc/net/if_inet6","r");
    if(f==NULL){
        log_out("/n Read conf file failed");
        return;
    }

    while(20==fscanf(f,
        "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%*x%x%x%x%s",
        &ipv6[0],
        &ipv6[1],
        &ipv6[2],
        &ipv6[3],
        &ipv6[4],
        &ipv6[5],
        &ipv6[6],
        &ipv6[7],
        &ipv6[8],
        &ipv6[9],
        &ipv6[10],
        &ipv6[11],
        &ipv6[12],
        &ipv6[13],
        &ipv6[14],
        &ipv6[15],
        &prefix,
        &scope,
        &ifa_flag,
        dname))
    {

        if(inet_ntop(AF_INET6,ipv6,address,sizeof(address))==NULL){
            continue;
        }

        switch(scope){
        case IPV6_ADDR_GLOBAL:
                scopestr="Global";
        break;
        case IPV6_ADDR_LINKLOCAL:
                scopestr="Link";
        break;
        case IPV6_ADDR_SITELOCAL:
                scopestr="Site";
        break;
        case IPV6_ADDR_COMPATv4:
                scopestr="Compat";
        break;
        case IPV6_ADDR_LOOPBACK:
                scopestr="Host";
        break;
        default:
            scopestr="Unknown";
        }

        log_out("\n IPv6address:%s \n > prefix:%d scope:%s ifaflag:%d dname:%s",address,prefix,scopestr.c_str(),ifa_flag,dname);
    }

    fclose(f);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void Test_TimeStamp()
{
    timespec ts_CurTime;
    int ti_Ret = clock_gettime(CLOCK_BOOTTIME, &ts_CurTime);

    double tf_TimeStamp = 0.0;
    if(0 == ti_Ret)
    {
        tf_TimeStamp = ts_CurTime.tv_sec + ts_CurTime.tv_nsec * 1e-9;
    } else
    {
        int ti_ErrNo = errno;
        log_out("\n Falied to call clock_gettime(): ret %d err %d", ti_Ret, ti_ErrNo);
    }

    timeval ts_SystemTime;
    gettimeofday(&ts_SystemTime, nullptr);

    long td_Delta = ts_CurTime.tv_sec - ts_SystemTime.tv_sec;

    log_out("\n CurTime is: %lf \n %ld = %ld", tf_TimeStamp, ts_SystemTime.tv_sec, td_Delta);
}

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

    jstring ts_ret;
    char buffer[50];
    sprintf(buffer, "Build with android api lv %d", __ANDROID_API__);
    ls_All = buffer;

    Test_TimeStamp();

    log_out("\n -- Resolve host  --");
    Resolve_Host("ipv6.baidu.com");
    //Resolve_Host("www.tencent.com");
    Resolve_Host("localhost");

    log_out("\n");
    parse_inet6();

    ts_ret = env->NewStringUTF(ls_All.c_str());
    return ts_ret;
}
}