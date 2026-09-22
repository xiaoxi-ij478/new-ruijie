#include "common.h"

static struct AppInfo app_info;
static int sig_pipe[2] = { -1, -1 };

void handle_sigint(int sig)
{
    char i = 0;
    write(sig_pipe[1], &i, 1);
}

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    app_info.ether_socket = -1;
    app_info.send_addr.sll_family = AF_PACKET;
    app_info.send_addr.sll_protocol = htons(ETH_P_PAE);
    app_info.send_addr.sll_addr[0] = 0x01;
    app_info.send_addr.sll_addr[1] = 0xD0;
    app_info.send_addr.sll_addr[2] = 0xF8;
    app_info.send_addr.sll_addr[3] = 0x00;
    app_info.send_addr.sll_addr[4] = 0x00;
    app_info.send_addr.sll_addr[5] = 0x03;
    app_info.send_addr.sll_halen = 6;

    for (
        int opt = getopt(argc, argv, "u:p:s:i:");
        opt != -1;
        opt = getopt(argc, argv, "u:p:s:i:")
    )
        switch (opt) {
            case 'u':
                app_info.username = optarg;
                break;

            case 'p':
                app_info.password = optarg;
                break;

            case 's':
                app_info.service_name = optarg;
                break;

            case 'i':
                app_info.net_interface_name = optarg;
                break;

            case '?':
                return EXIT_FAILURE;
        }

    if (!app_info.username || !app_info.password || !app_info.net_interface_name) {
        fputs("username, password and net interface name are required\n", stderr);
        goto err;
    }

    if (!app_info.service_name)
        app_info.service_name = "";

    if (pipe(sig_pipe) == -1) {
        perror("pipe");
        goto err;
    }

    if (
        (app_info.ether_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_PAE))) == -1
    ) {
        perror("could not create ether socket");
        goto err;
    }

    if (
        (
            app_info.send_addr.sll_ifindex = if_nametoindex(app_info.net_interface_name)
        ) == -1
    ) {
        perror("could not get if index");
        goto err;
    }

    if (
        bind(
            app_info.ether_socket,
            (const struct sockaddr *)&app_info.send_addr,
            sizeof(app_info.send_addr)
        ) == -1
    ) {
        perror("could not bind to interface");
        goto err;
    }

    /////////////////////////////////////////////////
    // stage 1: send eapol start pkg
    /////////////////////////////////////////////////
    if (stage1(&app_info) == -1)
        goto err;

    /////////////////////////////////////////////////
    // stage 2: send eap identity pkg
    /////////////////////////////////////////////////
    if (stage2(&app_info) == -1)
        goto err;

    /////////////////////////////////////////////////
    // stage 3: send md5 challenge reply
    /////////////////////////////////////////////////
    if (stage3(&app_info) == -1)
        goto err;

    struct sigaction sigact;
    sigact.sa_handler = handle_sigint;
    sigact.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sigact, NULL);
    // keep it SIMPLE for now
    assert(!app_info.direct_comm_info.sam_hello_interval);
    assert(!app_info.hello_info.hello_enabled);
    struct SendRecvBuffer *srbuf = alloc_srbuf(0, 2000);

    while (true) {
        srbuf->recvbuflen = 0;
        struct sockaddr_ll raddr;
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(app_info.ether_socket, &fdset);
        FD_SET(sig_pipe[0], &fdset);

        if (
            select(
                MAX(app_info.ether_socket, sig_pipe[0]) + 1,
                &fdset,
                NULL,
                NULL,
                NULL
            ) == -1 &&
            errno != EINTR // maybe by SIGINT
        ) {
            perror("select");
            goto err;
        }

        if (FD_ISSET(sig_pipe[0], &fdset)) {
            puts("logging off");
            app_info.logout_reason = 1;
            stage4(&app_info);
            break;
        }

        if (FD_ISSET(app_info.ether_socket, &fdset)) {
            int l = recv_ether_packet(
                        app_info.ether_socket,
                        &raddr,
                        srbuf->recvbuf,
                        srbuf->recvbufsiz
                    );

            if (l == -1)
                goto err;

            if (
                l < (sizeof(struct IEEE8021XPacketHeader) + sizeof(struct EAPPacketHeader))
            ) {
                fputs("short packet read\n", stderr);
                continue;
            }

            if (
                srbuf->recvbuf_ieee8021x->header.type == IEEE8021X_EAP_PACKET &&
                srbuf->recvbuf_eap->header.status_code == EAP_CODE_FAILURE
            ) {
                puts("remote forced us to go offline");
                break;
            }
        }
    }

    ret = 0;
err:

    if (sig_pipe[0] != -1)
        close(sig_pipe[0]);

    if (sig_pipe[1] != -1)
        close(sig_pipe[1]);

    if (app_info.ether_socket != -1)
        close(app_info.ether_socket);

    return ret;
}
