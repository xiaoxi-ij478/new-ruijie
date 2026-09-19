#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

int get_interface_idx(const char *name)
{
    int s = socket(AF_PACKET, SOCK_RAW, 0);

    if (s == -1) {
        perror("could not create socket");
        return -1;
    }

    struct ifreq ifr;

    strncpy(ifr.ifrn_name, name, IFNAMSIZ);

    if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
        perror("could not get interface index");
        return -1;
    }

    close(s);
    return ifr.ifr_ifindex;
}

int send_ether_packet_no_reply(
    int fd,
    struct sockaddr_ll *addr,
    const void *buf,
    unsigned buflen
)
{
    if (sendto(fd, buf, buflen, 0, addr, sizeof(*addr)) == -1) {
        perror("sendto");
        return -1;
    }

    return 0;
}

int send_ether_packet(
    int fd,
    struct sockaddr_ll *addr,
    const void *buf,
    unsigned buflen,
    void **retbuf,
    unsigned *retbuflen
)
{
    if (sendto(fd, buf, buflen, 0, addr, sizeof(*addr)) == -1) {
        perror("sendto");
        return -1;
    }

    fd_set fdset;
    struct timeval timeout = {3, 0};
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);

    switch (select(fd + 1, &fdset, NULL, &fdset, &timeout)) {
        case -1:
            perror("select");
            return -1;

        case 0:
            fputs("waiting for ether packet return timeout", stderr);
            return -1;
    }

    if (!FD_ISSET(fd, &fdset)) {
        // can that happen?!
        return -1;
    }

    struct sockaddr_ll srcaddr;

    if (!(*retbuf = malloc(1 << 11))) { // should be enough for most nic
        perror("malloc");
        return -1;
    }

    *retbuflen = 1 << 11;
    int real_recvsize = recvfrom(
                            fd,
                            *retbuf,
                            *retbuflen,
                            0,
                            &srcaddr,
                            sizeof(srcaddr)
                        );

    if (real_recvsize == -1) {
        perror("recvfrom");
        return -1;
    }

    if (!(*retbuf = realloc(*retbuf, real_recvsize))) {
        perror("realloc");
        return -1;
    }

    *retbuflen = real_recvsize;
    return 0;
}


int main(int argc, char *argv[])
{
    int opt;
    char *username = NULL;
    char *password = NULL;
    char *service_name = NULL;
    char *net_interface_name = NULL;

    while ((opt = getopt(argc, argv, "u:p:s:i:")) != -1) {
        switch (opt) {
            case 'u':
                username = optarg;
                break;

            case 'p':
                password = optarg;
                break;

            case 's':
                service_name = optarg;
                break;

            case 'i':
                net_interface_name = optarg;
                break;

            case '?':
                return EXIT_FAILURE;
        }
    }

    if (!username || !password) {
        fputs("username or password is required", stderr);
        return EXIT_FAILURE;
    }

    // we assume the env has already done dhcp
    int ether_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_PAE));

    if (ether_socket == -1) {
        perror("could not create ether socket");
        return EXIT_FAILURE;
    }

    if (net_interface_name) {
        struct sockaddr_ll lladdr;
        lladdr.sll_family = AF_PACKET;
        lladdr.sll_protocol = htons(ETH_P_PAE);

        if ((lladdr.sll_ifindex = get_interface_idx(net_interface_name)) == -1)
            return EXIT_FAILURE;

        if (bind(ether_socket, &lladdr, sizeof(lladdr)) == -1) {
            perror("could not bind to interface");
            return EXIT_FAILURE;
        }
    }

    for (unsigned i = 0; i < 3; i++) {
    }
}
