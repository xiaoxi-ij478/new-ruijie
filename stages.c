#include "common.h"

int stage1(struct AppInfo *app_info)
{
    int ret = -1;
    struct SendRecvBuffer *srbuf = alloc_srbuf(2000, 2000);
    app_info->current_stage = 1;
    puts("sending eapol start pkg...");
    srbuf->sendbuflen = sizeof(struct IEEE8021XPacketHeader);
    srbuf->sendbuf_ieee8021x->header.version = 1;
    srbuf->sendbuf_ieee8021x->header.type = IEEE8021X_EAPOL_START;
    srbuf->sendbuf_ieee8021x->header.length = htons(0);

    if (
        append_private_properties(
            srbuf->sendbuf,
            srbuf->sendbufsiz,
            &srbuf->sendbuflen,
            app_info
        ) == -1
    )
        goto err;

    if (
        send_ether_packet(
            app_info->ether_socket,
            &app_info->send_addr,
            srbuf->sendbuf,
            srbuf->sendbuflen
        ) < 0
    )
        goto err;

    for (unsigned i = 0; i < 3; i++) {
        int l = recv_ether_packet_with_timeout(
                    app_info->ether_socket,
                    &app_info->send_addr,
                    srbuf->recvbuf,
                    srbuf->recvbufsiz,
                    3
                );

        if (l < 0)
            continue;

        if (
            l < (sizeof(struct IEEE8021XPacketHeader) + sizeof(struct EAPPacketHeader))
        ) {
            fputs("short packet read\n", stderr);
            continue;
        }

        srbuf->recvbuflen = l;
        break;
    }

    if (!srbuf->recvbuflen)
        goto err;

    puts("got reply");

    if (srbuf->recvbuf_ieee8021x->header.type != IEEE8021X_EAP_PACKET) {
        fputs("reply packet type is not eap packet\n", stderr);
        goto err;
    }

    if (
        check_eap_status_type(srbuf, app_info, EAP_CODE_REQUEST, EAP_IDENTITY) == -1
    )
        goto err;

    ret = 0;
err:
    app_info->last_recv_eap_id = srbuf->recvbuf_eap->header.id;
    free_srbuf(srbuf);
    return ret;
}

int stage2(struct AppInfo *app_info)
{
    int ret = -1;
    struct SendRecvBuffer *srbuf = alloc_srbuf(2000, 2000);
    app_info->current_stage = 2;
    srbuf->sendbuflen = (
                            sizeof(struct IEEE8021XPacketHeader) +
                            sizeof(struct EAPPacketHeader) +
                            1
                        );
    srbuf->sendbuf_ieee8021x->header.version = 1;
    srbuf->sendbuf_ieee8021x->header.type = IEEE8021X_EAP_PACKET;
    srbuf->sendbuf_ieee8021x->header.length = htons(5 + strlen(app_info->username));
    srbuf->sendbuf_eap->header.status_code = EAP_CODE_RESPONSE;
    srbuf->sendbuf_eap->header.id = app_info->last_recv_eap_id;
    srbuf->sendbuf_eap->header.length = htons(5 + strlen(app_info->username));
    srbuf->sendbuf_eap->with_type.type = EAP_IDENTITY;
    strncpy(
        srbuf->sendbuf_eap->with_type.extra,
        app_info->username,
        srbuf->sendbufsiz - srbuf->sendbuflen - 1
    );
    srbuf->sendbuflen += MIN(
                             srbuf->sendbufsiz - srbuf->sendbuflen - 1,
                             strlen(app_info->username)
                         );

    if (
        append_private_properties(
            srbuf->sendbuf,
            srbuf->sendbufsiz,
            &srbuf->sendbuflen,
            app_info
        ) == -1
    )
        goto err;

    puts("sending eap identity pkg...");

    if (
        send_ether_packet(
            app_info->ether_socket,
            &app_info->send_addr,
            srbuf->sendbuf,
            srbuf->sendbuflen
        ) < 0
    )
        goto err;

    for (unsigned i = 0; i < 10; i++) {
        int l = recv_ether_packet_with_timeout(
                    app_info->ether_socket,
                    &app_info->send_addr,
                    srbuf->recvbuf,
                    srbuf->recvbufsiz,
                    45
                );

        if (l < 0)
            continue;

        if (
            l < (sizeof(struct IEEE8021XPacketHeader) + sizeof(struct EAPPacketHeader))
        ) {
            fputs("short packet read\n", stderr);
            continue;
        }

        srbuf->recvbuflen = l;
        break;
    }

    if (!srbuf->recvbuflen)
        goto err;

    puts("got reply");

    if (srbuf->recvbuf_ieee8021x->header.type != IEEE8021X_EAP_PACKET) {
        fputs("reply packet type is not eap packet\n", stderr);
        goto err;
    }

    if (
        check_eap_status_type(
            srbuf,
            app_info,
            EAP_CODE_REQUEST,
            EAP_MD5_CHALLENGE
        ) == -1
    )
        goto err;

    assert(srbuf->recvbuf_eap->with_type.extra[0] == 16);
    memcpy(
        app_info->md5_challenge,
        &srbuf->recvbuf_eap->with_type.extra[1],
        srbuf->recvbuf_eap->with_type.extra[0]
    );

    if (ntohs(srbuf->recvbuf_eap->header.length) <= 22) {
        ret = 0;
        goto err;
    }

    for (unsigned i = 17; i < ntohs(srbuf->recvbuf_eap->header.length) - 5;) {
        assert(ntohl(*(uint32_t *)&srbuf->recvbuf_eap->with_type.extra[i]) == 0x1311);
        i += 4;

        switch (srbuf->recvbuf_eap->with_type.extra[i]) {
            case 0x2E:
                assert(srbuf->recvbuf_eap->with_type.extra[i + 1] == 3);
                app_info->should_encrypt_password_in_md5_response = (
                            srbuf->recvbuf_eap->with_type.extra[i + 2]
                        );
                break;

            case 0x66: {
                    assert(srbuf->recvbuf_eap->with_type.extra[i + 1] >= 2);
                    unsigned service_list_length = (
                                                       srbuf->recvbuf_eap->with_type.extra[i + 1] - 2
                                                   );
                    puts("service list:");
                    fputs("1. ", stdout);

                    for (unsigned p = 2, l = 1; p < service_list_length + 2; p++) {
                        if (srbuf->recvbuf_eap->with_type.extra[i + p] == '@') {
                            printf("\n%u: ", ++l);
                            continue;
                        }

                        putchar(srbuf->recvbuf_eap->with_type.extra[i + p]);
                    }

                    putchar('\n');
                    break;
                }
        }

        i += srbuf->recvbuf_eap->with_type.extra[i + 1];
    }

    ret = 0;
err:
    app_info->last_recv_eap_id = srbuf->recvbuf_eap->header.id;
    free_srbuf(srbuf);
    return ret;
}

int stage3(struct AppInfo *app_info)
{
    int ret = -1;
    struct SendRecvBuffer *srbuf = alloc_srbuf(2000, 2000);
    app_info->current_stage = 3;
    srbuf->sendbuflen = (
                            sizeof(struct IEEE8021XPacketHeader) +
                            sizeof(struct EAPPacketHeader) +
                            1
                        );
    srbuf->sendbuf_ieee8021x->header.version = 1;
    srbuf->sendbuf_ieee8021x->header.type = IEEE8021X_EAP_PACKET;
    srbuf->sendbuf_ieee8021x->header.length = htons(
                22 + strlen(app_info->username)
            );
    srbuf->sendbuf_eap->header.status_code = EAP_CODE_RESPONSE;
    srbuf->sendbuf_eap->header.id = app_info->last_recv_eap_id;
    srbuf->sendbuf_eap->header.length = htons(22 + strlen(app_info->username));
    srbuf->sendbuf_eap->with_type.type = EAP_MD5_CHALLENGE;
    srbuf->sendbuf_eap->with_type.extra[0] = 16;
    srbuf->sendbuflen++;
    {
        md5_ctx ctx;
        rhash_md5_init(&ctx);
        rhash_md5_update(&ctx, &app_info->last_recv_eap_id, 1);
        rhash_md5_update(&ctx, app_info->password, strlen(app_info->password));
        rhash_md5_update(
            &ctx,
            app_info->md5_challenge,
            sizeof(app_info->md5_challenge)
        );
        rhash_md5_final(&ctx, &srbuf->sendbuf_eap->with_type.extra[1]);
        srbuf->sendbuflen += 16;
    }
    strncpy(
        &srbuf->sendbuf_eap->with_type.extra[17],
        app_info->username,
        srbuf->sendbufsiz - srbuf->sendbuflen - 1
    );
    srbuf->sendbuflen += MIN(
                             srbuf->sendbufsiz - srbuf->sendbuflen - 1,
                             strlen(app_info->username)
                         );
    app_info->responsing_md5_challenge = true;

    if (
        append_private_properties(
            srbuf->sendbuf,
            srbuf->sendbufsiz,
            &srbuf->sendbuflen,
            app_info
        ) == -1
    )
        goto err;

    app_info->responsing_md5_challenge = false;
    puts("sending eap md5 challenge pkg...");

    if (
        send_ether_packet(
            app_info->ether_socket,
            &app_info->send_addr,
            srbuf->sendbuf,
            srbuf->sendbuflen
        ) < 0
    )
        goto err;

    for (unsigned i = 0; i < 3; i++) {
        int l = recv_ether_packet_with_timeout(
                    app_info->ether_socket,
                    &app_info->send_addr,
                    srbuf->recvbuf,
                    srbuf->recvbufsiz,
                    3
                );

        if (l < 0)
            continue;

        if (
            l < (sizeof(struct IEEE8021XPacketHeader) + sizeof(struct EAPPacketHeader))
        ) {
            fputs("short packet read\n", stderr);
            continue;
        }

        srbuf->recvbuflen = l;
        break;
    }

    if (!srbuf->recvbuflen)
        goto err;

    puts("got reply");

    if (srbuf->recvbuf_ieee8021x->header.type != IEEE8021X_EAP_PACKET) {
        fputs("reply packet type is not eap packet\n", stderr);
        goto err;
    }

    if (
        check_eap_status_type(srbuf, app_info, EAP_CODE_SUCCESS, EAP_IDENTITY) == -1
    )
        goto err;

    ret = 0;
err:
    app_info->last_recv_eap_id = srbuf->recvbuf_eap->header.id;
    free_srbuf(srbuf);
    return ret;
}
