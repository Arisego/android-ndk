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

#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <dirent.h>

#define IPV6_ADDR_GLOBAL        0x0000U
#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U
#define IPV6_ADDR_COMPATv4      0x0080U

#include <String>
std::string ls_All;

void parse_inet6(const char *ifname) {
    FILE *f;
    int ret, scope, prefix;
    unsigned char ipv6[16];
    char dname[IFNAMSIZ];
    char address[INET6_ADDRSTRLEN];
    char *scopestr;

    f = fopen("/proc/net/if_inet6", "r");
    if (f == NULL) {
        return;
    }

    while (19 == fscanf(f,
                        " %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %x %x %*x %s",
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
                        dname)) {

        if (inet_ntop(AF_INET6, ipv6, address, sizeof(address)) == NULL) {
            continue;
        }

        switch (scope) {
            case IPV6_ADDR_GLOBAL:
                scopestr = "Global";
                break;
            case IPV6_ADDR_LINKLOCAL:
                scopestr = "Link";
                break;
            case IPV6_ADDR_SITELOCAL:
                scopestr = "Site";
                break;
            case IPV6_ADDR_COMPATv4:
                scopestr = "Compat";
                break;
            case IPV6_ADDR_LOOPBACK:
                scopestr = "Host";
                break;
            default:
                scopestr = "Unknown";
        }

        LOGW("IPv6 address: %s, prefix: %d, scope: %s\n", address, prefix, scopestr);

        char buffer[150];
        sprintf(buffer,"IPv6 address: %s, prefix: %d, scope: %s dname: %s\n", address, prefix, scopestr, dname);
        ls_All += buffer;
    }

    fclose(f);
}

void parse_ioctl(const char *ifname)
{
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *ipaddr;
    char address[INET_ADDRSTRLEN];
    size_t ifnamelen;

    /* copy ifname to ifr object */
    ifnamelen = strlen(ifname);
    if (ifnamelen >= sizeof(ifr.ifr_name)) {
        return ;
    }
    memcpy(ifr.ifr_name, ifname, ifnamelen);
    ifr.ifr_name[ifnamelen] = '\0';

    /* open socket */
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        return;
    }

    /* process mac */
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != -1) {
        LOGW("Mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned char)ifr.ifr_hwaddr.sa_data[0],
               (unsigned char)ifr.ifr_hwaddr.sa_data[1],
               (unsigned char)ifr.ifr_hwaddr.sa_data[2],
               (unsigned char)ifr.ifr_hwaddr.sa_data[3],
               (unsigned char)ifr.ifr_hwaddr.sa_data[4],
               (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    }

    /* process mtu */
    if (ioctl(sock, SIOCGIFMTU, &ifr) != -1) {
        LOGW("MTU: %d\n", ifr.ifr_mtu);
    }

    /* die if cannot get address */
    if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
        close(sock);
        return;
    }

    /* process ip */
    ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    if (inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address)) != NULL) {
        LOGW("Ip address: %s\n", address);
    }

    /* try to get broadcast */
    if (ioctl(sock, SIOCGIFBRDADDR, &ifr) != -1) {
        ipaddr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
        if (inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address)) != NULL) {
            LOGW("Broadcast: %s\n", address);
        }
    }

    /* try to get mask */
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) != -1) {
        ipaddr = (struct sockaddr_in *)&ifr.ifr_netmask;
        if (inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address)) != NULL) {
            LOGW("Netmask: %s\n", address);
        }
    }

    close(sock);
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
    sprintf(buffer, "Everything is right %d", 12);

    DIR *d;
    struct dirent *de;

    d = opendir("/sys/class/net/");
    if (d == NULL) {
        sprintf(buffer, "/sys/class/net/ open failed");

        parse_inet6("fake");
        ls_All += "\n [route from fake call]";
        ts_ret = env->NewStringUTF(ls_All.c_str());
    } else{
        while (NULL != (de = readdir(d))) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }

            LOGW("Interface %s\n", de->d_name);
            parse_ioctl(de->d_name);
            parse_inet6(de->d_name);

            LOGW("\n");
        }
        closedir(d);

        ts_ret = env->NewStringUTF(ls_All.c_str());
    }
    return ts_ret;
}
}