#include "common.h"

int get_interface_hwaddr(const char *name, struct sockaddr *ret)
{
    if (!name || !ret) {
        fputs("name or ret ptr null\n", stderr);
        return -1;
    }

    int s = socket(AF_PACKET, SOCK_RAW, 0);

    if (s == -1) {
        perror("could not create socket");
        return -1;
    }

    struct ifreq ifr;

    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("could not get interface hardware address");
        close(s);
        return -1;
    }

    *ret = ifr.ifr_hwaddr;
    return 0;
}

int get_interface_addr(const char *name, struct IPInfo *ret)
{
    if (!name || !ret) {
        fputs("name or ret ptr null\n", stderr);
        return -1;
    }

    int s = socket(AF_PACKET, SOCK_RAW, 0);

    if (s == -1) {
        perror("could not create socket");
        return -1;
    }

    struct ifreq ifr;

    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        perror("could not get interface address");

        if (errno == EADDRNOTAVAIL)
            fputs("you may need to do dhcp first\n", stderr);

        close(s);
        return -1;
    }

    ret->addr = *(struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(s, SIOCGIFNETMASK, &ifr) < 0) {
        perror("could not get interface netmask");
        close(s);
        return -1;
    }

    ret->netmask = *(struct sockaddr_in *)&ifr.ifr_addr;
    FILE *routefp = fopen("/proc/net/route", "r");

    if (!routefp) {
        perror("could not open route file");
        close(s);
        return -1;
    }

    char buffer[200] = { 0 };
    bool gateway_found = false;
    fgets(buffer, sizeof(buffer), routefp);

    while (fgets(buffer, sizeof(buffer), routefp)) {
        unsigned dest;
        struct sockaddr_in gateway;
        char local_name[30] = { 0 };

        if (
            sscanf(buffer, "%s %x %x", local_name, &dest, &gateway.sin_addr.s_addr) < 3
        ) {
            perror("could not parse route file");
            fclose(routefp);
            close(s);
            return -1;
        }

        if (!strcmp(local_name, name) && !dest) {
            gateway.sin_addr.s_addr = ntohl(gateway.sin_addr.s_addr);
            ret->gateway = gateway;
            gateway_found = true;
            break;
        }
    }

    fclose(routefp);

    if (!gateway_found) {
        fputs("gateway could not be found\n", stderr);
        close(s);
        return -1;
    }

    FILE *ifinet6fp = fopen("/proc/net/if_inet6", "r");

    if (!routefp) {
        perror("could not open if_inet6 file");
        close(s);
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), ifinet6fp)) {
        char ifname[50];
        unsigned b[2];

        if (sscanf(buffer, "%*s %*s %*s %*s %*s %s", ifname) < 1) {
            perror("could not parse if_inet6 file");
            fclose(ifinet6fp);
            close(s);
            return -1;
        }

#define STORE_LOCAL \
    sscanf( \
            buffer, \
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx" \
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", \
            &ret->local_v6addr.sin6_addr.s6_addr[0], \
            &ret->local_v6addr.sin6_addr.s6_addr[1], \
            &ret->local_v6addr.sin6_addr.s6_addr[2], \
            &ret->local_v6addr.sin6_addr.s6_addr[3], \
            &ret->local_v6addr.sin6_addr.s6_addr[4], \
            &ret->local_v6addr.sin6_addr.s6_addr[5], \
            &ret->local_v6addr.sin6_addr.s6_addr[6], \
            &ret->local_v6addr.sin6_addr.s6_addr[7], \
            &ret->local_v6addr.sin6_addr.s6_addr[8], \
            &ret->local_v6addr.sin6_addr.s6_addr[9], \
            &ret->local_v6addr.sin6_addr.s6_addr[10], \
            &ret->local_v6addr.sin6_addr.s6_addr[11], \
            &ret->local_v6addr.sin6_addr.s6_addr[12], \
            &ret->local_v6addr.sin6_addr.s6_addr[13], \
            &ret->local_v6addr.sin6_addr.s6_addr[14], \
            &ret->local_v6addr.sin6_addr.s6_addr[15] \
          )
#define STORE_GLOBAL \
    sscanf( \
            buffer, \
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx" \
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", \
            &ret->global_v6addr.sin6_addr.s6_addr[0], \
            &ret->global_v6addr.sin6_addr.s6_addr[1], \
            &ret->global_v6addr.sin6_addr.s6_addr[2], \
            &ret->global_v6addr.sin6_addr.s6_addr[3], \
            &ret->global_v6addr.sin6_addr.s6_addr[4], \
            &ret->global_v6addr.sin6_addr.s6_addr[5], \
            &ret->global_v6addr.sin6_addr.s6_addr[6], \
            &ret->global_v6addr.sin6_addr.s6_addr[7], \
            &ret->global_v6addr.sin6_addr.s6_addr[8], \
            &ret->global_v6addr.sin6_addr.s6_addr[9], \
            &ret->global_v6addr.sin6_addr.s6_addr[10], \
            &ret->global_v6addr.sin6_addr.s6_addr[11], \
            &ret->global_v6addr.sin6_addr.s6_addr[12], \
            &ret->global_v6addr.sin6_addr.s6_addr[13], \
            &ret->global_v6addr.sin6_addr.s6_addr[14], \
            &ret->global_v6addr.sin6_addr.s6_addr[15] \
          )

        if (strcmp(ifname, name))
            continue;

        sscanf(buffer,"%02hhx%02hhx", &b[0], &b[1]);

        if (b[0] == 0xfe) {
            if ((b[1] & 0xc0) == 0x80)
                STORE_LOCAL;

            else if ((b[1] & 0xc0) == 0xc0)
                STORE_GLOBAL;

        } else if ((b[0] & 0xe0) == 0x20)
            STORE_GLOBAL;
    }

#undef STORE_LOCAL
#undef STORE_GLOBAL
    close(s);
    return 0;
}

int send_ether_packet(
    int fd,
    struct sockaddr_ll *addr,
    const void *buf,
    unsigned buflen
)
{
    if (
        sendto(fd, buf, buflen, 0, (const struct sockaddr *)addr, sizeof(*addr)) == -1
    ) {
        perror("sendto");
        return -1;
    }

    return 0;
}

int recv_ether_packet_with_timeout(
    int fd,
    struct sockaddr_ll *srcaddr,
    void *retbuf,
    unsigned retbuflen,
    unsigned timeout_s
)
{
    if (!retbuf) {
        fputs("ret buf pointer null\n", stderr);
        return -1;
    }

    fd_set fdset;
    struct timeval timeout = { timeout_s, 0 };
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);

    switch (select(fd + 1, &fdset, NULL, NULL, timeout_s ? &timeout : NULL)) {
        case -1:
            perror("select");
            return -1;

        case 0:
            fputs("waiting for ether packet return timeout\n", stderr);
            return -2;
    }

    if (!FD_ISSET(fd, &fdset))
        // can that happen?!
        return -1;

    unsigned saddr_siz = sizeof(*srcaddr);
    int real_recvsize = recvfrom(
                            fd,
                            retbuf,
                            retbuflen,
                            0,
                            (struct sockaddr *)srcaddr,
                            &saddr_siz
                        );

    if (real_recvsize == -1) {
        perror("recvfrom");
        return -1;
    }

    return real_recvsize;
}

int recv_ether_packet(
    int fd,
    struct sockaddr_ll *srcaddr,
    void *retbuf,
    unsigned retbuflen
)
{
    return recv_ether_packet_with_timeout(fd, srcaddr, retbuf, retbuflen, 0);
}
