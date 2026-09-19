#include <string.h>
#include "rc4.h"

static void swap(unsigned char *s1, unsigned char *s2)
{
    unsigned char temp;
    temp = *s1;
    *s1 = *s2;
    *s2 = temp;
}

void re_S(unsigned char *S)
{
    int i;

    for (i = 0; i < 256; i++)
        S[i] = i;
}

void re_T(unsigned char *T, const unsigned char *key)
{
    int i;
    int keylen;
    keylen = strlen((const char *)key);

    for (i = 0; i < 256; i++)
        T[i] = key[i % keylen];
}

void re_Sbox(unsigned char *S, unsigned char *T)
{
    int i;
    int j = 0;

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        swap(&S[i], &S[j]);
    }
}

void RC4(unsigned char *text, const unsigned char *key, int txtlen)
{
    unsigned char S[256] = { 0 };
    int i, k, l;
    unsigned char T[256] = { 0 };
    re_S(S);
    re_T(T, key);
    re_Sbox(S, T);
    i = k = l = 0;

    while (k < txtlen) {
        i++;
        i &= 255;
        l += S[i];
        l &= 255;
        swap(&S[i], &S[l]);
        text[k] = text[k] ^ S[(S[i] + S[l]) & 255];
        k++;
//        text[k] = text[k] ^ S[i];
//        i = (i + 1) % 256;
//        k++;
    }
}
