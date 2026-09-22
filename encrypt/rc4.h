#ifndef RC4_H_INCLUDED
#define RC4_H_INCLUDED

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void RC4(uint8_t *text, const uint8_t *key, int txtlen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // RC4_H_INCLUDED
