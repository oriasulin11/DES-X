#ifndef DES_X
#include "des.h"
#include <time.h>
// Encrypt and Decrypt any block
uint64_t encrypt_block_des_x(uint64_t* block, uint64_t* subkeys, uint64_t k1, uint64_t k2);
uint64_t decrypt_block_des_x(uint64_t * block, uint64_t * subkeys, uint64_t k1, uint64_t k2);
// Encrypt and Decrypt blocks in ecb mode
uint64_t * encrypt_ecb_mode(uint64_t* blocks, int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2);
uint64_t * decrypt_ecb_mode(uint64_t* blocks, int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2);
// Encrypt and Decrypt blocks in cbc mode
uint64_t* encrypt_cbc_mode(uint64_t* blocks, int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t * IV);
uint64_t* decrypt_cbc_mode(uint64_t* blocks, int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t * IV);
// Encrypt and Decrypt blocks in cfb mode
uint64_t* encrypt_cfb_mode(uint64_t* plaintext_blocks, int num_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* iv);
uint64_t* decrypt_cfb_mode(uint64_t* ciphertext_blocks, int num_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* iv);

void generate_des_x_keys(uint64_t* K1, uint64_t* K2);

#endif // !DES_X

