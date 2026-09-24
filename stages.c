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

    unsigned current_pos = 0;
#define VERIFY_PROPERTY_MAGIC_AND_SKIP do { \
        assert( \
                ntohl(*(uint32_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos]) == 0x1311 \
              ); \
        current_pos += 4; \
    } while (0)
#define GET_PROPERTY_LENGTH_AND_SKIP ({ \
        unsigned l = ntohs(*(uint16_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos]); \
        current_pos += 2; \
        l; \
    })
    {
        VERIFY_PROPERTY_MAGIC_AND_SKIP;
        unsigned l = GET_PROPERTY_LENGTH_AND_SKIP;
        printf("remote notification: ");
        fwrite(&srbuf->recvbuf_eap->without_type.extra[current_pos], 1, l, stdout);
        putchar('\n');
        current_pos += l;
    }

    {
        VERIFY_PROPERTY_MAGIC_AND_SKIP;
        unsigned l = GET_PROPERTY_LENGTH_AND_SKIP;
        printf(
            "remote report latest version: %#x\n",
            ntohl(*(uint32_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos])
        );
        current_pos += l;
    }

    {
        VERIFY_PROPERTY_MAGIC_AND_SKIP;
        printf(
            "remote report proxy detection is %svalid and %senabled\n",
            srbuf->recvbuf_eap->without_type.extra[current_pos] ? "" : "in",
            srbuf->recvbuf_eap->without_type.extra[current_pos + 1] ? "" : "not "
        );
        current_pos += 2;
    }

    {
        VERIFY_PROPERTY_MAGIC_AND_SKIP;
        current_pos += 2;
    }

    {
        for (unsigned i = 0; i < 15; i++)
            srbuf->recvbuf_eap->without_type.extra[current_pos + i] = scramble(
                    srbuf->recvbuf_eap->without_type.extra[current_pos + i]
                );

        VERIFY_PROPERTY_MAGIC_AND_SKIP;
        assert(srbuf->recvbuf_eap->without_type.extra[current_pos] == 10);
        current_pos++;
        app_info->hello_info.hello_enabled = srbuf->recvbuf_eap->without_type.extra[current_pos];
        printf(
            "remote report eap hello %s enabled, with id %#x and interval %u secs\n",
            app_info->hello_info.hello_enabled ? "" : "not",
            ntohl(*(uint32_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos + 1]),
            ntohl(*(uint32_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos + 5])
        );
        current_pos += 10;
    }

#undef VERIFY_PROPERTY_MAGIC_AND_SKIP
#undef GET_PROPERTY_LENGTH_AND_SKIP

    while (current_pos < ntohs(srbuf->recvbuf_eap->header.length) - 4) {
        unsigned magic = ntohl(
                             *(uint32_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos]
                         );
        unsigned char type = srbuf->recvbuf_eap->without_type.extra[current_pos + 4];
        unsigned char length = srbuf->recvbuf_eap->without_type.extra[current_pos + 5];
        current_pos += 6;
        assert(magic == 0x1311);
#define GET_U8_AT(pos) (srbuf->recvbuf_eap->without_type.extra[current_pos])
#define GET_U16_AT(pos) ntohs(*(uint16_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos])
#define GET_U32_AT(pos) ntohl(*(uint32_t *)&srbuf->recvbuf_eap->without_type.extra[current_pos])

        switch (type) {
            case 0x37:
                fputs("remote report upgrade url: ", stdout);
                fwrite(
                    &srbuf->recvbuf_eap->without_type.extra[current_pos],
                    1,
                    length - 2,
                    stdout
                );
                putchar('\n');
                break;

            case 0x3c:
                fputs("remote report account info: ", stdout);
                fwrite(
                    &srbuf->recvbuf_eap->without_type.extra[current_pos],
                    1,
                    length - 2,
                    stdout
                );
                putchar('\n');
                break;

            case 0x3d:
                fputs("remote report personal info: ", stdout);
                fwrite(
                    &srbuf->recvbuf_eap->without_type.extra[current_pos],
                    1,
                    length - 2,
                    stdout
                );
                putchar('\n');
                break;

            case 0x56:
                // reconnect interval, we do not use this
                printf("remote report reconnect interval: %u mins\n", GET_U32_AT(0));
                break;

            case 0x59:
                printf(
                    "remote report sam hello interval: %u secs\n",
                    app_info->direct_comm_info.sam_hello_interval = GET_U32_AT(0)
                );
                break;

            case 0x5a:
                printf(
                    "remote report sam server port: %hu\n",
                    app_info->direct_comm_info.sam_addr.sin_port = GET_U32_AT(0)
                );
                break;

            case 0x5b:
                app_info->direct_comm_info.sam_addr.sin_addr.s_addr = htonl(GET_U32_AT(0));
                printf(
                    "remote report sam server ip: %s\n",
                    inet_ntoa(app_info->direct_comm_info.sam_addr.sin_addr)
                );
                break;

            case 0x5c:
                RC4(&srbuf->recvbuf_eap->without_type.extra[current_pos], "com.ruijie.www", 8);
                memcpy(
                    app_info->direct_comm_info.sam_encrypt_key,
                    &srbuf->recvbuf_eap->without_type.extra[current_pos],
                    8
                );
                fputs("remote report sam encrypt key: ", stdout);

                for (unsigned i = 0; i < 8; i++)
                    printf("%02x", GET_U8_AT(i));

                putchar('\n');
                break;

            case 0x5d:
                RC4(&srbuf->recvbuf_eap->without_type.extra[current_pos], "com.ruijie.www", 8);
                memcpy(
                    app_info->direct_comm_info.sam_encrypt_iv,
                    &srbuf->recvbuf_eap->without_type.extra[current_pos],
                    8
                );
                fputs("remote report sam encrypt iv: ", stdout);

                for (unsigned i = 0; i < 8; i++)
                    printf("%02x", GET_U8_AT(i));

                putchar('\n');
                break;

            case 0x5e:
                printf(
                    "remote report sam server utc timestamp: %llu\n",
                    (
                        app_info->direct_comm_info.sam_server_utc_timestamp = be64toh(
                                *(uint64_t*)&srbuf->recvbuf_eap->without_type.extra[current_pos]
                            )
                    )
                );
                break;

            case 0x61:
                assert(GET_U8_AT(0) == 9);
                break;

            case 0x65:
                fputs("remote report service switch result: ", stdout);
                fwrite(
                    &srbuf->recvbuf_eap->without_type.extra[current_pos],
                    1,
                    length - 2,
                    stdout
                );
                putchar('\n');
                break;

            case 0x66:
                // service list, we already fetched at stage 2
                break;

            case 0x68:
                fputs("remote report user login url: ", stdout);
                fwrite(
                    &srbuf->recvbuf_eap->without_type.extra[current_pos],
                    1,
                    length - 2,
                    stdout
                );
                putchar('\n');
                break;

            case 0x6e:
                // msg client port for smp, ignore
                break;

            case 0x72:
                fputs("remote report utrust url: ", stdout);
                fwrite(&srbuf->recvbuf_eap->without_type.extra[current_pos], 1, length - 2,
                       stdout);
                putchar('\n');
                break;

            case 0x74:
                fputs("remote report proxy detection type:", stdout);

                if (GET_U8_AT(0) & 4)
                    fputs(" HTTP", stdout);

                if (GET_U8_AT(0) & 2)
                    fputs(" SOCKS4/5", stdout);

                putchar('\n');
                break;

            case 0x77:
                printf(
                    "remote report %s to show utrust url, with delay %u secs",
                    GET_U8_AT(0) ? "wants" : "do not want",
                    GET_U16_AT(1)
                );
                break;

            case 0x79:
                printf(
                    "remote report direct communication highest version supported: %u\n",
                    (
                        app_info->direct_comm_info.sam_direct_comm_supported_highest_version =
                            GET_U8_AT(0)
                    )
                );
                break;

            case 0x80:
                printf(
                    "remote report direct communication heartbeat flags: %u\n",
                    (
                        app_info->direct_comm_info.sam_direct_comm_heartbeat_flags = GET_U8_AT(0)
                    )
                );
                break;

            default:
                printf("received unknown property with type %#x\n", type);
                break;
        }

#undef GET_U8_AT
#undef GET_U16_AT
#undef GET_U32_AT
        current_pos += length - 2;
    }

    ret = 0;
err:
    app_info->last_recv_eap_id = srbuf->recvbuf_eap->header.id;
    free_srbuf(srbuf);
    return ret;
}

int stage4(struct AppInfo*app_info)
{
    int ret = -1;
    struct SendRecvBuffer *srbuf = alloc_srbuf(2000, 0);
    app_info->current_stage = 4;
    srbuf->sendbuflen = sizeof(struct IEEE8021XPacketHeader);
    srbuf->sendbuf_ieee8021x->header.version = 1;
    srbuf->sendbuf_ieee8021x->header.type = IEEE8021X_EAPOL_LOGOFF;
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

    ret = 0;
err:
    free_srbuf(srbuf);
    return ret;
}
