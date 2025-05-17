#ifndef PROCESS_INPUT_H
#define PROCESS_INPUT_H
#define BYTES_IN_BLOCK 8
#define MAX_CHARS 25000
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>


// Define a string
typedef char String[MAX_CHARS];

uint8_t* read_file(const char* filename, size_t* length);

uint64_t* process_raw_bytes_to_blocks(uint8_t* data, size_t len, int* block_count, int is_ciphertext);
int file_exists(const char* path);
// Function to apply CMS padding to the last block
void apply_cms_padding(uint64_t  * block, uint8_t bytes_used);

// Function to handle input and split it into 64-bit blocks with CMS padding
void process_input_to_blocks(String plaintext, uint64_t** blocks, int* num_blocks);

// Function to handle input and split it into 64-bit blocks with CMS padding
void process_cipher_text_to_blocks(String plaintext, uint64_t** blocks, int* num_blocks);

// Function to getting user input and processing it
uint64_t* get_user_input_and_process(int *, char *, int);

// Function to convert uint64_t to ascii
void convert_block_to_text(uint64_t block, String output);

// Get master Key from User.
void get_master_key(uint64_t* master_key);

#endif // PROCESS_INPUT_H
