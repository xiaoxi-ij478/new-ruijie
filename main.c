#include "common.h"

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    struct AppInfo app_info = { -1 };
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

    // we assume the env has already done dhcp

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
    )
        goto err;

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

    ret = 0;
err:

    if (app_info.ether_socket != -1)
        close(app_info.ether_socket);

    return ret;
}
