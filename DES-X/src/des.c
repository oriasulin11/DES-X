#include <stdio.h>
#include "des.h"
#include <stdlib.h>
#include <string.h>
#include "tables.h"

void reverse_array(uint64_t* arr, int size) {
    int left = 0, right = size - 1;

    while (left < right) {
        // Swap elements
        uint64_t temp = arr[left];
        arr[left] = arr[right];
        arr[right] = temp;

        // Move pointers
        left++;
        right--;
    }
}

uint64_t apply_permutation(uint64_t input, const uint8_t* table, size_t output_size) {
    uint64_t output = 0;
    for (int i = 0; i < output_size; i++) {
        // Get bit from position specified by the table
        uint64_t bit = (input >> (64 - table[i])) & 1;
        // Set bit in output
        output |= (bit << (output_size - i - 1));
    }
    return output;
}
// Uses the expanding table to expand 32-bit to 48-bit
uint64_t expand_32_bit(uint32_t right_half) {
    uint64_t expanded = 0;

    for (int i = 0; i < 48; i++) {
        // Get bit position from expansion
        uint8_t bit_pos = E[i];
        // Get the bit from the right half
        uint64_t bit = (right_half >> (32 - bit_pos)) & 1;
        // Set bit in expanded result
        expanded |= (bit << (47 - i));
    }
    return expanded;
}
// Apply 8 s-boxes and reduce from 48-bit to 32 bit
uint32_t apply_s_boxes(uint64_t expanded) {
    uint32_t s_box_output = 0;
    // 6 bits at a time to produce 4 bits each
    for (uint8_t i = 0; i < S_BOXES_COUNT; i++) {
        // Extract 6 bits for this S-box
        uint8_t s_box_input = (expanded >> (42 - i * 6)) & 0x3F;

        // Compute row and column for S-box lookup
        uint8_t row = ((s_box_input & 0x20) >> 4) | (s_box_input & 0x01);
        uint8_t col = (s_box_input >> 1) & 0x0F;

        // Get 4-bit output from S-box
        uint8_t s_value = S_BOXES[i][row][col];

        // Add to output
        s_box_output |= ((uint32_t)s_value << (28 - i * 4));
    }
    return s_box_output;
}
uint32_t apply_32_bit_permutation(uint32_t input) {
    uint32_t result = 0;
    for (int i = 0; i < 32; i++) {
        // Get bit position from P-box
        int bit_pos = P[i];
        // Get the bit from the S-box output
        uint32_t bit = (input >> (31 - bit_pos)) & 0x01;
        // Set bit in result
        result |= (bit << (31 - i));
    }
    return result;
}
uint64_t encrypt_block(uint64_t* plaintext,uint64_t * subkeys)
{
    // save the output of each round function
    uint64_t temp, round_key, cipher_text;
    // Apply initial permuutation
    temp = apply_permutation(*plaintext, IP, 64);
    
    
    // Apply round function 16 times 
    for (int round = 0; round < NUMBER_OF_ROUNDS; round++)
    {
        round_key =subkeys[round];
        // Apply a DES round
        temp = des_round(temp,round_key);
    }
    // Preform 32 bit swap
    cipher_text = temp;
    cipher_text = ((temp & 0xFFFFFFFF) << 32) | (temp >> 32);

    // Perform final Permutation
    cipher_text = apply_permutation(cipher_text, FP, 64);

    return cipher_text;

}
// The core F-function of DES
uint32_t f_function(uint32_t right_half, uint64_t subkey) {
    // Step 1: Expand 32-bit right half to 48 bits
    uint64_t expanded = expand_32_bit(right_half);

    // Step 2: XOR with the subkey
    expanded ^= subkey;

    // Step 3: Apply S-boxes
    uint32_t s_box_output = apply_s_boxes(expanded);

    // Step 4: Apply P-box permutation
    uint32_t result = apply_32_bit_permutation(s_box_output);

    return result;
}
// One round of DES encryption
uint64_t des_round(uint64_t block, uint64_t subkey) {
    uint32_t right_half = block & 0xFFFFFFFF;
    uint32_t left_half = block >> 32;

    // Apply F-function
    uint32_t f_result = f_function(right_half, subkey);

    // New right half = left_half XOR F(right_half, subkey)
    uint32_t new_right = left_half ^ f_result;

    // Swap halves: right_half becomes new left, and new_right becomes new right
    uint64_t new_block = ((uint64_t)right_half << 32) | new_right;

    return new_block;
}

uint64_t decrypt_block(uint64_t* ciphertext, uint64_t* subkeys)
{
    reverse_array(subkeys, 16);  // Reverse for decryption
    uint64_t plaintext = encrypt_block(ciphertext, subkeys);
    reverse_array(subkeys, 16); // Restore original order
    return plaintext;
}

