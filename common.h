#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <endian.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/param.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "hash/crc16.h"
#include "hash/md5.h"
#include "hash/whirlpool.h"
#include "hash/tiger.h"
#include "hash/sha1.h"
#include "hash/ripemd128.h"

#include "encrypt/rc4.h"
#include "encrypt/d3des.h"

enum IEEE8021XPacketType {
    IEEE8021X_EAP_PACKET,
    IEEE8021X_EAPOL_START,
    IEEE8021X_EAPOL_LOGOFF
};

enum EAPPacketStatusCode {
    EAP_CODE_REQUEST = 1,
    EAP_CODE_RESPONSE,
    EAP_CODE_SUCCESS,
    EAP_CODE_FAILURE
};

enum EAPPacketType {
    EAP_IDENTITY = 1,
    EAP_NOTIFICATION,
    EAP_NAK,
    EAP_MD5_CHALLENGE
};

struct IPInfo {
    struct sockaddr_in addr;
    struct sockaddr_in6 global_v6addr;
    struct sockaddr_in6 local_v6addr;
    struct sockaddr_in netmask;
    struct sockaddr_in gateway;
};

struct __attribute__((packed)) IEEE8021XPacketHeader {
    uint8_t version;
    uint8_t type;
    uint16_t length;
};

struct __attribute__((packed)) EAPPacketHeader {
    uint8_t status_code;
    uint8_t id;
    uint16_t length;
};

struct __attribute__((packed)) IEEE8021XPacket {
    struct IEEE8021XPacketHeader header;
    uint8_t extra[];
};

struct __attribute__((packed)) EAPPacket {
    struct EAPPacketHeader header;
    union {
        struct {
            uint8_t type;
            uint8_t extra[0];
        } with_type;

        struct {
            uint8_t extra[0];
        } without_type;
    };
};

struct SendRecvBuffer {
    void *sendbuf, *recvbuf;
    struct IEEE8021XPacket *sendbuf_ieee8021x, *recvbuf_ieee8021x;
    struct EAPPacket *sendbuf_eap, *recvbuf_eap;
    unsigned sendbuflen, recvbuflen;
    unsigned sendbufsiz, recvbufsiz;
};

struct HelloInfo {
    bool hello_enabled;
    unsigned hello_id;
    unsigned hello_interval;
};

struct DirectCommInfo {
    unsigned sam_hello_interval;
    struct sockaddr_in sam_addr;
    uint8_t sam_encrypt_key[8];
    uint8_t sam_encrypt_iv[8];
    uint64_t sam_server_utc_timestamp;
    unsigned char sam_direct_comm_supported_highest_version;
    unsigned char sam_direct_comm_heartbeat_flags;
};

struct AppInfo {
    int ether_socket;
    struct sockaddr_ll send_addr;
    char *username;
    char *password;
    char *service_name;
    char *net_interface_name;
    uint8_t md5_challenge[16];
    unsigned current_stage;
    unsigned logout_reason;
    uint8_t last_recv_eap_id;
    bool should_encrypt_password_in_md5_response;
    bool responsing_md5_challenge;
    struct HelloInfo hello_info;
    struct DirectCommInfo direct_comm_info;
};

static inline struct IEEE8021XPacket *get_ieee8021x_packet(void *buf)
{
    return (struct IEEE8021XPacket *)buf;
}

static inline struct EAPPacket *get_eap_packet(void *buf)
{
    return (struct EAPPacket *)get_ieee8021x_packet(buf)->extra;
}

static inline struct SendRecvBuffer *alloc_srbuf(
    unsigned sendsz,
    unsigned recvsz
)
{
    struct SendRecvBuffer *ret = malloc(sizeof(struct SendRecvBuffer));
    assert((ret->recvbuf = calloc(1, sendsz)));
    assert((ret->sendbuf = calloc(1, sendsz)));
    ret->sendbuf_ieee8021x = get_ieee8021x_packet(ret->sendbuf);
    ret->recvbuf_ieee8021x = get_ieee8021x_packet(ret->recvbuf);
    ret->sendbuf_eap = get_eap_packet(ret->sendbuf);
    ret->recvbuf_eap = get_eap_packet(ret->recvbuf);
    ret->sendbufsiz = sendsz;
    ret->recvbufsiz = recvsz;
    ret->sendbuflen = ret->recvbuflen = 0;
    return ret;
}

static inline void free_srbuf(struct SendRecvBuffer *b)
{
    free(b->recvbuf);
    free(b->sendbuf);
    free(b);
}

static inline uint8_t scramble(uint8_t b)
{
    return (
               ((~b & 0x80) >> 7) |
               ((~b & 0x40) >> 5) |
               ((~b & 0x20) >> 3) |
               ((~b & 0x10) >> 1) |
               ((~b & 0x08) << 1) |
               ((~b & 0x04) << 3) |
               ((~b & 0x02) << 5) |
               ((~b & 0x01) << 7)
           );
}

extern const unsigned char appdata[1820];
extern const unsigned char dlldata[2035];
extern const unsigned char heart_beat_array[6784];

int stage1(struct AppInfo *app_info);
int stage2(struct AppInfo *app_info);
int stage3(struct AppInfo *app_info);
int stage4(struct AppInfo *app_info);
int get_interface_hwaddr(const char *name, struct sockaddr *ret);
int get_interface_addr(const char *name, struct IPInfo *ret);
int send_ether_packet(
    int fd,
    struct sockaddr_ll *addr,
    const void *buf,
    unsigned buflen
);
int recv_ether_packet_with_timeout(
    int fd,
    struct sockaddr_ll *srcaddr,
    void *retbuf,
    unsigned retbuflen,
    unsigned timeout_s
);
int recv_ether_packet(
    int fd,
    struct sockaddr_ll *srcaddr,
    void *retbuf,
    unsigned retbuflen
);
int check_eap_status_type(
    struct SendRecvBuffer *srbuf,
    struct AppInfo *app_info,
    unsigned expect_status,
    unsigned expect_type
);
int append_private_properties(
    void *buf,
    unsigned bufsiz,
    unsigned *bufpos,
    struct AppInfo *app_info
);

#endif // COMMON_H_INCLUDED
