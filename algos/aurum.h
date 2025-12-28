#ifndef AURUM_H
#define AURUM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int PHS(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);
void aurum_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // AURUM_H
