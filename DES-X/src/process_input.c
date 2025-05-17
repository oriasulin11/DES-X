#include "process_input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma warning(disable:4996)

int file_exists(const char* path) {
    struct stat buffer;
    return (stat(path, &buffer) == 0);
}

uint8_t* read_file(const char* filename, size_t* length) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file");
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* buffer = (uint8_t*)malloc(*length);
    if (!buffer) {
        fprintf(stderr, "Error opening file");
        exit(1);
    }

    fread(buffer, 1, *length, file);
    fclose(file);

    return buffer;
}
uint64_t* process_raw_bytes_to_blocks(uint8_t* data, size_t len, int* block_count, int is_ciphertext) {
    size_t full_blocks = len / 8;
    size_t remainder = len % 8;
  
    if (!is_ciphertext)
        *block_count = (len + 7) / 8;  // round up with zero padding
    else
        *block_count = full_blocks;   // exact block count for ciphertext

    uint64_t* blocks = (uint64_t*)calloc(*block_count, sizeof(uint64_t));
    if (!blocks) {
        fprintf(stderr, "Error opening file");

        exit(1);
    }

    for (int i = 0; i < *block_count; i++) {
        for (int j = 0; j < 8 && (i * 8 + j) < len; j++) {
            blocks[i] |= ((uint64_t)(unsigned char)data[i * 8 + j] << (8 * j));
            
        }
    }

    return blocks;
}
// Function to apply CMS padding to the last block
// In CMS padding, each padding byte has a value equal to the number of padding bytes
void apply_cms_padding(uint64_t* block, uint8_t bytes_used) {
    uint8_t padding_value = BYTES_IN_BLOCK - bytes_used;

    // Fill the remaining bytes with the padding value
    for (int index = bytes_used; index < 8; index++) {
        *block |= ((uint64_t)padding_value << (8 * index));
    }
}

// Function to handle input and split it into 64-bit blocks with CMS padding
void process_input_to_blocks(String plaintext, uint64_t** blocks, int* num_blocks) {
    uint16_t len = strlen(plaintext);
    *num_blocks = (len % 8 == 0) ? (len / 8) : (len / 8 + 1);

    *blocks = (uint64_t*)calloc(*num_blocks, sizeof(uint64_t));
    if (!*blocks) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    int full_blocks = len / 8;
    int remaining = len % 8;

    for (int i = 0; i < *num_blocks; i++) {
        for (int j = 0; j < 8 && (i * 8 + j) < len; j++) {
            (*blocks)[i] |= ((uint64_t)(unsigned char)plaintext[i * 8 + j]) << (8 * j);
        }
    }

    if (remaining > 0)
        apply_cms_padding(&((*blocks)[full_blocks]), remaining);

}

void process_cipher_text_to_blocks(String input, uint64_t** blocks, int* num_blocks)
{
    // Count lines = number of ciphertext blocks
    int count = 0;
    char* input_copy = strdup(input);  // Make a copy for tokenizing
    char* line = strtok(input_copy, "\n");
    while (line) {
        count++;
        line = strtok(NULL, "\n");
    }
    free(input_copy);

    *blocks = (uint64_t*)calloc(count, sizeof(uint64_t));
    if (!*blocks) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    // Tokenize and convert hex strings to uint64_t
    int index = 0;
    line = strtok(input, "\n");
    while (line && index < count) {
        (*blocks)[index++] = strtoull(line, NULL, 16);
        line = strtok(NULL, "\n");
    }

    *num_blocks = count;
}

// Function to get user input and process it
uint64_t* get_user_input_and_process(int* number_of_blocks, char* input, int is_ciphertext) {
    // Dynamic array of blocks
    uint64_t* blocks;
    int num_blocks = 0;



    // Remove newline character if present
    int input_len = strlen(input);
    if (input_len > 0 && input[input_len - 1] == '\n') {
        input[input_len - 1] = '\0';
        input_len--;
    }

    if (is_ciphertext) {
        // Count lines = number of ciphertext blocks
        char* input_copy = strdup(input);  // Make a copy for tokenizing
        char* line = strtok(input_copy, "\n");
        while (line) {
            num_blocks++;
            line = strtok(NULL, "\n");
        }
        free(input_copy);

        blocks = (uint64_t*)calloc(num_blocks, sizeof(uint64_t));
        if (!blocks) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }

        // Tokenize and convert hex strings to uint64_t
        int index = 0;
        line = strtok(input, "\n");
        while (line) {
            blocks[index++] = strtoull(line, NULL, 16);
            line = strtok(NULL, "\n");
        }
    }
    else {
        // Plaintext processing
        process_input_to_blocks(input, &blocks, &num_blocks);
    }

    *number_of_blocks = num_blocks;

    return blocks;
}
void convert_block_to_text(uint64_t block, String output) {
    for (int i = 0; i < 8; i++) {
        output[i] = (char)(block & 0xFF); // Extract the lowest byte
        block >>= 8; // Shift right by 8 bits to process the next byte
    }
    output[8] = '\0'; // Null-terminate the string
}

void get_master_key(uint64_t* master_key)
{
    char pass[16];
    printf("Enter a 8 character master key: ");
    gets_s(pass, 9);
    memcpy(master_key, pass, 8);
}
