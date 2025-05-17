#ifndef DES_H
#define DES_H

#define S_BOXES_COUNT 8
#define NUMBER_OF_ROUNDS 16
#define AFFECTIVE_SUBKEY_SIZE 48
#include <stdint.h>
#include "process_input.h"
#include "tables.h"
#include "clebsch.h"

uint64_t apply_permutation(uint64_t input, const uint8_t* table, size_t output_size);
uint64_t expand_32_bit(uint32_t right_half);
uint32_t f_function(uint32_t right_half, uint64_t subkey);
uint32_t apply_s_boxes(uint64_t expanded);
uint32_t apply_32_bit_permutation(uint32_t input);
uint64_t encrypt_block(uint64_t* plaintext, uint64_t * subkeys);
uint64_t des_round(uint64_t block, uint64_t subkey);
uint64_t decrypt_block(uint64_t* ciphertext, uint64_t * subkeys);
void reverse_array(uint64_t* arr, int size);

#endif
