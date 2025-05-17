#include <stdio.h>
#include<string.h>
#include "process_input.h"
#include "des.h"
#include<math.h>
#include "tables.h"
#include "des_x.h"
#pragma warning(disable:4996)

int is_file_output = 0;
int is_encrypting = 0;

void handle_ecb_mode_encryption(uint64_t* blocks, int number_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2) {
    uint64_t* encrypted = encrypt_ecb_mode(blocks, number_of_blocks, subkeys, k1, k2);
    for (int i = 0; i < number_of_blocks; i++) {
        if (is_file_output)
            fwrite(&encrypted[i], sizeof(uint64_t), 1, stdout);
        else
            printf("%016llX\n", (unsigned long long)encrypted[i]);
    }
    free(encrypted);
}

void handle_ecb_mode_decryption(uint64_t* blocks, int number_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2) {
    uint64_t* decrypted = decrypt_ecb_mode(blocks, number_of_blocks, subkeys, k1, k2);
    for (int i = 0; i < number_of_blocks; i++) {
        fwrite(&decrypted[i], sizeof(uint64_t), 1, stdout);
    }
    free(decrypted);
}

void handle_cbc_mode_encryption(uint64_t* blocks, int number_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* IV) {
    uint64_t* encrypted = encrypt_cbc_mode(blocks, number_of_blocks, subkeys, k1, k2, IV);
    for (int i = 0; i < number_of_blocks; i++) {
        if (is_file_output)
            fwrite(&encrypted[i], sizeof(uint64_t), 1, stdout);
        else
            printf("%016llX\n", (unsigned long long)encrypted[i]);
    }
    free(encrypted);
}

void handle_cbc_mode_decryption(uint64_t* blocks, int number_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* IV) {
    uint64_t* decrypted = decrypt_cbc_mode(blocks, number_of_blocks, subkeys, k1, k2, IV);
    for (int i = 0; i < number_of_blocks; i++) {
        fwrite(&decrypted[i], sizeof(uint64_t), 1, stdout);
    }
    free(decrypted);
}

void handle_cfb_mode_encryption(uint64_t* blocks, int number_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* IV) {
    
    uint64_t* encrypted = encrypt_cfb_mode(blocks, number_of_blocks, subkeys, k1, k2, IV);
    for (int i = 0; i < number_of_blocks; i++) {
        if (is_file_output)
            fwrite(&encrypted[i], sizeof(uint64_t), 1, stdout);
        else
            printf("%016llX\n", (unsigned long long)encrypted[i]);

    }
    free(encrypted);
}

void handle_cfb_mode_decryption(uint64_t* blocks, int number_of_blocks, uint64_t* subkeys, uint64_t k1, uint64_t k2, uint64_t* IV) {
    uint64_t* decrypted = decrypt_cfb_mode(blocks, number_of_blocks, subkeys, k1, k2, IV);
    for (int i = 0; i < number_of_blocks; i++) {
        fwrite(&decrypted[i], sizeof(uint64_t), 1, stdout);
    }
    free(decrypted);
}

int main(int argc, char* argv[]) {
    if (argc != 9) {
        fprintf(stderr, "Usage: %s <input or filepath> <masterKey> <k1> <k2> <iv> <mode> <isCiphertext> <isFileOutput>\n", argv[0]);
        return 1;
    }

    const char* input = argv[1];
    const char* mode = argv[6];
    int is_ciphertext = !strcmp(argv[7], "1") ? 1 : 0;
    is_file_output = !strcmp(argv[8], "1") ? 1 : 0;
    is_encrypting = !is_ciphertext;

    uint64_t master_key = strtoull(argv[2], NULL, 10);
    uint64_t k1 = strtoull(argv[3], NULL, 10);
    uint64_t k2 = strtoull(argv[4], NULL, 10);
    uint64_t IV = strtoull(argv[5], NULL, 10);

    uint64_t* blocks;
    int number_of_blocks = 0;
    uint8_t* file_data = NULL;
    size_t file_size = 0;

    if (file_exists(input)) {
        file_data = read_file(input, &file_size);
        blocks = process_raw_bytes_to_blocks(file_data, file_size, &number_of_blocks, is_ciphertext);
        free(file_data);
    }
    else {
        blocks = get_user_input_and_process(&number_of_blocks, (char*)input, is_ciphertext);
    }

    uint64_t* subkeys = get_all_subkeys(master_key);

    if (!strcmp("ecb", mode)) {
        if (is_ciphertext)
            handle_ecb_mode_decryption(blocks, number_of_blocks, subkeys, k1, k2);
        else
            handle_ecb_mode_encryption(blocks, number_of_blocks, subkeys, k1, k2);
    }
    else if (!strcmp("cbc", mode)) {
        if (is_ciphertext)
            handle_cbc_mode_decryption(blocks, number_of_blocks, subkeys, k1, k2, &IV);
        else
            handle_cbc_mode_encryption(blocks, number_of_blocks, subkeys, k1, k2, &IV);
    }
    else if (!strcmp("cfb", mode)) {
        if (is_ciphertext)
            handle_cfb_mode_decryption(blocks, number_of_blocks, subkeys, k1, k2, &IV);
        else
            handle_cfb_mode_encryption(blocks, number_of_blocks, subkeys, k1, k2, &IV);
    }
    else {
        fprintf(stderr, "Invalid mode specified.\n");
    }

    free(subkeys);
    free(blocks);
    return 0;
}