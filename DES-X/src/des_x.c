#include "des_x.h"

uint64_t encrypt_block_des_x(uint64_t* block, uint64_t* subkeys, uint64_t k1, uint64_t k2)
{
    uint64_t post_encryption;
    uint64_t pre_encryption = *block ^ k1;                   // Pre-XOR with K1
    post_encryption = encrypt_block(&pre_encryption, subkeys);  // Encrypt                
    return post_encryption ^ k2;         // Post-XOR with K2
}

uint64_t decrypt_block_des_x(uint64_t *block, uint64_t* subkeys, uint64_t k1, uint64_t k2)
{
    uint64_t post_decryption;
    uint64_t pre_decryption = *block ^ k2; // Reverse XOR with K2
    post_decryption = decrypt_block(&pre_decryption, subkeys);  // Decrypt               
    return post_decryption ^ k1; // Reverse XOR with K1
}



uint64_t generate_random_key() {
    return ((uint64_t)rand() << 32) | rand(); // Generate 64-bit random number
}

void generate_des_x_keys(uint64_t* K1, uint64_t* K2)
{
    srand(time(NULL));  // Seed random number generator
    *K1 = generate_random_key();
    *K2 = generate_random_key();
}
uint64_t * encrypt_ecb_mode(uint64_t* blocks,int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2)
{
    // Dynamic array of encrypted blocks
    uint64_t* encrypted_blocks;
    encrypted_blocks = (uint64_t*)calloc(num_of_blocks, sizeof(uint64_t));

    if (encrypted_blocks == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    // Encrypt each block
    for (int index = 0; index < num_of_blocks; index++)
        encrypted_blocks[index] = encrypt_block_des_x(&(blocks[index]), subkeys, k1, k2);
    return encrypted_blocks;
    
}
uint64_t* decrypt_ecb_mode(uint64_t* blocks, int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2)
{
    // Dynamic array of decrypted blocks
    uint64_t* decrypted_blocks;
    decrypted_blocks = (uint64_t*)calloc(num_of_blocks, sizeof(uint64_t));

    if (decrypted_blocks == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    // Decrypt each block
    for (int index = 0; index < num_of_blocks; index++)
        decrypted_blocks[index] = decrypt_block_des_x(&(blocks[index]), subkeys, k1, k2);
    return decrypted_blocks;

}

uint64_t* encrypt_cbc_mode(uint64_t* blocks, int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* IV)
{
    uint64_t* encrypted_blocks = (uint64_t*)malloc(num_of_blocks * sizeof(uint64_t));
    if (encrypted_blocks == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    uint64_t prev_cipher = *IV;

    for (int i = 0; i < num_of_blocks; i++) {
        uint64_t xor_input = blocks[i] ^ prev_cipher;  // CBC XOR step
        encrypted_blocks[i] = encrypt_block_des_x(&xor_input, subkeys, k1, k2);
        prev_cipher = encrypted_blocks[i];  // Update IV for next block
    }
    return encrypted_blocks;
}
uint64_t* decrypt_cbc_mode(uint64_t* blocks, int num_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* IV) {
    uint64_t* decrypted_blocks = (uint64_t*)malloc(num_of_blocks * sizeof(uint64_t));
    if (decrypted_blocks == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    uint64_t prev_cipher = *IV;

    for (int i = 0; i < num_of_blocks; i++) {
        uint64_t decrypted = decrypt_block_des_x(&(blocks[i]), subkeys, k1, k2);
        decrypted_blocks[i] = decrypted ^ prev_cipher;  // Reverse CBC XOR step
        prev_cipher = blocks[i];  // Update IV for next block
    }
    return decrypted_blocks;
}

uint64_t* encrypt_cfb_mode(uint64_t* plaintext_blocks, int num_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* iv) {
    uint64_t* ciphertext = (uint64_t*)malloc(sizeof(uint64_t) * num_blocks);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed in CFB encryption\n");
        exit(1);
    }

    uint64_t feedback = *iv;

    for (int i = 0; i < num_blocks; i++) {
        uint64_t encrypted_feedback = encrypt_block_des_x(&feedback, subkeys, k1, k2);
        ciphertext[i] = encrypted_feedback ^ plaintext_blocks[i];
        feedback = ciphertext[i];
    }

    return ciphertext;
}

uint64_t* decrypt_cfb_mode(uint64_t* ciphertext_blocks, int num_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* iv) {
    uint64_t* plaintext = (uint64_t*)malloc(sizeof(uint64_t) * num_blocks);
    if (!plaintext) {
        fprintf(stderr, "Memory allocation failed in CFB decryption\n");
        exit(1);
    }

    uint64_t feedback = *iv;

    for (int i = 0; i < num_blocks; i++) {
        uint64_t encrypted_feedback = encrypt_block_des_x(&feedback, subkeys, k1, k2);
        plaintext[i] = encrypted_feedback ^ ciphertext_blocks[i];
        feedback = ciphertext_blocks[i];
    }

    return plaintext;
}