#ifndef TABLES_H
#define TABLES_H

#include <stdint.h>

extern const uint8_t IP[64];   // Initial Permutation
extern const uint8_t FP[64];   // Final Permutation
extern const uint8_t E[48];    // Expansion Table
extern const uint8_t P[32];    // Permutation Table
extern const uint8_t PC2[48];    // Permutated Choice 2 Table
extern const uint8_t S_BOXES[8][4][16]; // S-Boxes

#endif // TABLES_H
