#ifndef RC4_H_INCLUDED
#define RC4_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void re_S(unsigned char *S);
void re_T(unsigned char *T, const unsigned char *key);
void re_Sbox(unsigned char *S, unsigned char *T);
void RC4(unsigned char *text, const unsigned char *key, int txtlen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // RC4_H_INCLUDED
