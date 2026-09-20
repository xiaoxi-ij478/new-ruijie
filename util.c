#include "common.h"

int check_eap_status_type(
    struct SendRecvBuffer *srbuf,
    struct AppInfo *app_info,
    unsigned expect_status,
    unsigned expect_type
)
{
    if (srbuf->recvbuf_eap->header.status_code != expect_status)
        switch (srbuf->recvbuf_eap->header.status_code) {
            case EAP_CODE_FAILURE:
                assert(ntohl(*(uint32_t *)srbuf->recvbuf_eap->without_type.extra) == 0x1311);
                fputs("error from remote: ", stderr);
                // TODO convert to utf8
                fwrite(
                    &srbuf->recvbuf_eap->without_type.extra[6],
                    1,
                    ntohs(*(uint16_t *)&srbuf->recvbuf_eap->without_type.extra[4]),
                    stderr
                );
                fputc('\n', stderr);
                return -1;

            default:
                fputs("remote returned unknown status code\n", stderr);
                return -1;
        }

    if (expect_status != EAP_CODE_REQUEST && expect_status != EAP_CODE_RESPONSE)
        return 0;

    if (srbuf->recvbuf_eap->with_type.type != expect_type)
        switch (srbuf->recvbuf_eap->with_type.type) {
            case EAP_NOTIFICATION:
                fputs("error from remote: ", stderr);
                fwrite(
                    srbuf->recvbuf_eap->with_type.extra,
                    1,
                    ntohs(srbuf->recvbuf_eap->header.length) - 5,
                    stderr
                );
                fputc('\n', stderr);
                return -1;

            default:
                srbuf->sendbuflen = (
                                        sizeof(struct IEEE8021XPacketHeader) +
                                        sizeof(struct EAPPacketHeader) +
                                        1
                                    );
                srbuf->sendbuf_ieee8021x->header.version = 1;
                srbuf->sendbuf_ieee8021x->header.type = IEEE8021X_EAP_PACKET;
                srbuf->sendbuf_ieee8021x->header.length = htons(5);
                srbuf->sendbuf_eap->header.status_code = EAP_CODE_RESPONSE;
                srbuf->sendbuf_eap->header.id = srbuf->recvbuf_eap->header.id;
                srbuf->sendbuf_eap->header.length = htons(5);
                srbuf->sendbuf_eap->with_type.type = EAP_NAK;

                if (
                    append_private_properties(
                        srbuf->sendbuf,
                        srbuf->sendbufsiz,
                        &srbuf->sendbuflen,
                        app_info
                    ) == -1
                )
                    return -1;

                send_ether_packet(
                    app_info->ether_socket,
                    &app_info->send_addr,
                    srbuf->sendbuf,
                    srbuf->sendbuflen
                );
                return -1;
        }

    return 0;
}

// bufpos will be updated
int append_private_properties(
    void *buf,
    unsigned bufsiz,
    unsigned *bufpos,
    struct AppInfo *app_info
)
{
    unsigned char *local_buf = (unsigned char *)buf;
#define CHECK_BUFSIZ(size) do { if (*bufpos + (size) >= bufsiz) { fputs("buffer will overflow\n", stderr); return -1; } } while (0)
#define PUT_U32(val) do { CHECK_BUFSIZ(4); *(uint32_t *)(&local_buf[*bufpos]) = htonl(val); *bufpos += 4; } while (0)
#define PUT_U16(val) do { CHECK_BUFSIZ(2); *(uint16_t *)(&local_buf[*bufpos]) = htons(val); *bufpos += 2; } while (0)
#define PUT_U8(val) do { CHECK_BUFSIZ(1); local_buf[(*bufpos)++] = (val); } while (0)
#define PUT_U32_RAW(val) do { CHECK_BUFSIZ(4); *(uint32_t *)(&local_buf[*bufpos]) = (val); *bufpos += 4; } while (0)
#define PUT_U16_RAW(val) do { CHECK_BUFSIZ(2); *(uint16_t *)(&local_buf[*bufpos]) = (val); *bufpos += 2; } while (0)
#define PUT_U8_RAW(val) do { CHECK_BUFSIZ(4); *(uint32_t *)(&local_buf[*bufpos]) = (val); *bufpos += 4; } while (0)
#define PUT_STRING(str) do { CHECK_BUFSIZ(strlen(str)); memcpy(&local_buf[*bufpos], (str), strlen(str)); *bufpos += strlen(str); } while (0)
#define PUT_STRING_WITH_PADDING(str, len) do { CHECK_BUFSIZ(len); strncpy((char *)&local_buf[*bufpos], (str), (len)); *bufpos += (len); } while (0)
#define PUT_STRING_WITH_NULL(str) do { CHECK_BUFSIZ(strlen(str) + 1); strcpy((char *)&local_buf[*bufpos], (str)); *bufpos += strlen(str) + 1; } while (0)
    {
        struct IPInfo ipinfo;

        if (get_interface_addr(app_info->net_interface_name, &ipinfo) == -1)
            return -1;

        PUT_U32(0x1311);
        PUT_U8(1); // dhcp enabled
        PUT_U32_RAW(ipinfo.addr.sin_addr.s_addr); // ip addr
        PUT_U32_RAW(ipinfo.netmask.sin_addr.s_addr); // netmask
        PUT_U32_RAW(ipinfo.gateway.sin_addr.s_addr); // gateway
        PUT_U32(0x7F000001); // dns (i was lazy so just fake one, 127.0.0.1)
        uint16_t c16 = crc16(&local_buf[*bufpos - 21], 21);
        PUT_U16(c16);

        for (unsigned i = 0; i < 23; i++)
            local_buf[*bufpos - 23 + i] = scramble(local_buf[*bufpos - 23 + i]);
    } {
        PUT_U32(0x1311);
        PUT_STRING_WITH_PADDING("8021x.exe", 32); // app name
    } {
        PUT_U8(0x01);
        PUT_U8(0x1E);
        PUT_U8(0x01);
        PUT_U8(0x02);
    } {
        PUT_U8(app_info->logout_reason);
        PUT_U32(0x1311);
        PUT_U8(0x00);
        PUT_U8(0x00);
    }
#define MAKE_PRIVATE_PROPERTY(length, type) \
    { \
        PUT_U8(0x1A); \
        PUT_U8((length) + 8); \
        PUT_U32(0x1311); \
        PUT_U8(type); \
        PUT_U8((length) + 2); \
    }
    MAKE_PRIVATE_PROPERTY(4, 0x18) {
        PUT_U32(0x01); // dhcp enabled
    }
    MAKE_PRIVATE_PROPERTY(6, 0x2D) {
        struct sockaddr hwaddr;

        if (get_interface_hwaddr(app_info->net_interface_name, &hwaddr) == -1)
            return -1;

        for (unsigned i = 0; i < 6; i++)
            PUT_U8(hwaddr.sa_data[i]);
    }

    if (app_info->should_encrypt_password_in_md5_response) {
        md5_ctx ctx;
        unsigned orig_password_len = strlen(app_info->password);
        unsigned aligned_password_len = (orig_password_len + 15) & ~15;
        char *outbuf = malloc(aligned_password_len);
        char tmpbuf[16];
        memcpy(tmpbuf, app_info->md5_challenge, 16);
        MAKE_PRIVATE_PROPERTY(aligned_password_len, 0x2F) {
            for (unsigned i = 0; i < aligned_password_len; i += 16) {
                rhash_md5_init(&ctx);
                rhash_md5_update(&ctx, app_info->username, strlen(app_info->username));
                rhash_md5_update(&ctx, tmpbuf, 16);
                rhash_md5_final(&ctx, tmpbuf);

                for (unsigned j = 0; j < 16; j++) {
                    tmpbuf[j] ^= (i >= orig_password_len ? 0 : app_info->password[i]);
                    PUT_U8(tmpbuf[j]);
                }
            }

            free(outbuf);
        }

    } else {
        MAKE_PRIVATE_PROPERTY(0, 0x2F) {
        }
    }

    MAKE_PRIVATE_PROPERTY(0, 0x76) {
        // alternative dnses, just assume to be none
    }
    MAKE_PRIVATE_PROPERTY(1, 0x35) {
        PUT_U8(2);
    }
    MAKE_PRIVATE_PROPERTY(16, 0x36) {
        for (unsigned i = 0; i < 16; i++)
            PUT_U8(0);
    }
    MAKE_PRIVATE_PROPERTY(16, 0x38) {
        struct IPInfo ipinfo;

        if (get_interface_addr(app_info->net_interface_name, &ipinfo) == -1)
            return -1;

        for (unsigned i = 0; i < 16; i++)
            PUT_U8(ipinfo.local_v6addr.sin6_addr.s6_addr[i]);
    }
    MAKE_PRIVATE_PROPERTY(16, 0x4E) {
        struct IPInfo ipinfo;

        if (get_interface_addr(app_info->net_interface_name, &ipinfo) == -1)
            return -1;

        for (unsigned i = 0; i < 16; i++)
            PUT_U8(ipinfo.global_v6addr.sin6_addr.s6_addr[i]);
    }
    MAKE_PRIVATE_PROPERTY(128, 0x4D) {
        if (app_info->responsing_md5_challenge) {
            char whbuf[1000] = { 0 };
            unsigned char whash[64];
            char whash_ascii[129] = { 0 };

            switch ((app_info->md5_challenge[0] + app_info->md5_challenge[3]) % 5) {
                case 0: {
                        unsigned char mhash1[16], mhash2[16];
                        md5_ctx mctx1, mctx2;
                        rhash_md5_init_Vz(&mctx1);
                        rhash_md5_init_Vz(&mctx2);
                        rhash_md5_update_Vz(&mctx1, appdata, sizeof(appdata));
                        rhash_md5_update_Vz(&mctx2, dlldata, sizeof(dlldata));
                        rhash_md5_final_Vz(&mctx1, mhash1);
                        rhash_md5_final_Vz(&mctx2, mhash2);

                        for (unsigned i = 0; i < sizeof(mhash1); i++)
                            sprintf(whbuf, "%02x", mhash1[i]);

                        for (unsigned i = 0; i < sizeof(app_info->md5_challenge); i += 2)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        for (unsigned i = 0; i < sizeof(mhash2); i++)
                            sprintf(whbuf, "%02x", mhash2[i]);

                        for (unsigned i = 1; i < sizeof(app_info->md5_challenge); i += 2)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        break;
                    }

                case 1: {
                        unsigned char shash1[20], shash2[20];
                        sha1_ctx sctx1, sctx2;
                        rhash_sha1_init_Vz(&sctx1);
                        rhash_sha1_init_Vz(&sctx2);
                        rhash_sha1_update_Vz(&sctx1, dlldata, sizeof(dlldata));
                        rhash_sha1_update_Vz(&sctx2, appdata, sizeof(appdata));
                        rhash_sha1_final_Vz(&sctx1, shash1);
                        rhash_sha1_final_Vz(&sctx2, shash2);

                        for (unsigned i = 0; i < sizeof(shash1); i++)
                            sprintf(whbuf, "%02x", shash1[i]);

                        for (unsigned i = 0; i < 6; i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        for (unsigned i = 0; i < sizeof(shash1); i++)
                            sprintf(whbuf, "%02x", shash2[i]);

                        for (unsigned i = 6; i < sizeof(app_info->md5_challenge); i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        break;
                    }

                case 2: {
                        unsigned char shash[20];
                        unsigned char rihash[16];
                        sha1_ctx sctx;
                        struct ampheck_ripemd128 rctx;
                        rhash_sha1_init_Vz(&sctx);
                        ampheck_ripemd128_init_Vz(&rctx);
                        rhash_sha1_update_Vz(&sctx, dlldata, sizeof(dlldata));
                        ampheck_ripemd128_update_Vz(&rctx, appdata, sizeof(appdata));
                        rhash_sha1_final_Vz(&sctx, shash);
                        ampheck_ripemd128_finish_Vz(&rctx, rihash);

                        for (unsigned i = 0; i < sizeof(shash); i++)
                            sprintf(whbuf, "%02x", shash[i]);

                        for (unsigned i = 0; i < 6; i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        for (unsigned i = 0; i < sizeof(rihash); i++)
                            sprintf(whbuf, "%02x", rihash[i]);

                        for (unsigned i = 6; i < sizeof(app_info->md5_challenge); i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        break;
                    }

                case 3: {
                        unsigned char thash[24];
                        unsigned char rihash[16];
                        tiger_ctx tctx;
                        struct ampheck_ripemd128 rctx;
                        rhash_tiger_init_Vz(&tctx);
                        ampheck_ripemd128_init_Vz(&rctx);
                        rhash_tiger_update_Vz(&tctx, appdata, sizeof(appdata));
                        ampheck_ripemd128_update_Vz(&rctx, dlldata, sizeof(dlldata));
                        rhash_tiger_final_Vz(&tctx, thash);
                        ampheck_ripemd128_finish_Vz(&rctx, rihash);

                        for (unsigned i = 0; i < sizeof(thash); i++)
                            sprintf(whbuf, "%02x", thash[i]);

                        for (unsigned i = 0; i < 10; i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        for (unsigned i = 0; i < sizeof(rihash); i++)
                            sprintf(whbuf, "%02x", rihash[i]);

                        for (unsigned i = 10; i < sizeof(app_info->md5_challenge); i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        break;
                    }

                case 4: {
                        unsigned char thash[24];
                        unsigned char shash[20];
                        tiger_ctx tctx;
                        sha1_ctx sctx;
                        rhash_tiger_init_Vz(&tctx);
                        rhash_sha1_init_Vz(&sctx);
                        rhash_tiger_update_Vz(&tctx, appdata, sizeof(appdata));
                        rhash_sha1_update_Vz(&sctx, dlldata, sizeof(dlldata));
                        rhash_tiger_final_Vz(&tctx, thash);
                        rhash_sha1_final_Vz(&sctx, shash);

                        for (unsigned i = 0; i < sizeof(thash); i++)
                            sprintf(whbuf, "%02x", thash[i]);

                        for (unsigned i = 0; i < 8; i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        for (unsigned i = 0; i < sizeof(shash); i++)
                            sprintf(whbuf, "%02x", shash[i]);

                        for (unsigned i = 8; i < sizeof(app_info->md5_challenge); i++)
                            sprintf(whbuf, "%02x", app_info->md5_challenge[i]);

                        break;
                    }
            }

            whirlpool_ctx wctx;
            rhash_whirlpool_init_Vz(&wctx);
            rhash_whirlpool_update_Vz(&wctx, whbuf, strlen(whbuf));
            rhash_whirlpool_final_Vz(&wctx, whash);

            for (unsigned i = 0; i < sizeof(whash); i++)
                sprintf(whash_ascii, "%02x", whash[i]);

            PUT_STRING(whash_ascii);

        } else
            PUT_STRING(
                "cedfeb1d7f714546e57ca23b56e1888b"
                "1c576780b68da2764b2da9badf68fe79"
                "130740975965232c5a5e36b00c09401d"
                "0fd81179a318b66587ff9e49aa98f5d0"
            );

        /*
         *  calculated by:
         *  the vz whirlpool of {
         *      the vz md5 of g_pAppData @ src/global.cpp +
         *      "0" * 15 +
         *      the vz md5 of g_pDllData @ src/global.cpp +
         *      "0" * 15
         *  }
         */
    }
    MAKE_PRIVATE_PROPERTY(32, 0x39) {
        PUT_STRING_WITH_PADDING(app_info->service_name, 32);
    }
    MAKE_PRIVATE_PROPERTY(64, 0x54) {
        // disk id (nothing for privacy)
        PUT_STRING_WITH_PADDING("MX_00000000000030368", 64);
    }
    MAKE_PRIVATE_PROPERTY(0, 0x55) {
    }
    MAKE_PRIVATE_PROPERTY(1, 0x62) {
        PUT_U8(0x00);
    }
    MAKE_PRIVATE_PROPERTY(1, 0x70) {
        // os bits, we choose to always be 64bit
        PUT_U8(64);
    }
    MAKE_PRIVATE_PROPERTY(strlen("RG-SU For Linux V1.30") + 1, 0x6F) {
        PUT_STRING_WITH_NULL("RG-SU For Linux V1.30");
    }
    MAKE_PRIVATE_PROPERTY(1, 0x79) {
        PUT_U8(0x02);
    }
#undef MAKE_PRIVATE_PROPERTY
#undef CHECK_BUFSIZ
#undef PUT_STRING_WITH_NULL
#undef PUT_STRING_WITH_PADDING
#undef PUT_STRING
#undef PUT_U8_RAW
#undef PUT_U16_RAW
#undef PUT_U32_RAW
#undef PUT_U8
#undef PUT_U16
#undef PUT_U32
    return 0;
}
