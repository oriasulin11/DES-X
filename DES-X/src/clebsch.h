#ifndef CLEBSCH_H
#define CLEBSCH_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "tables.h"

#define NUM_VERTICES 16
#define SEGMENT_BITS 4  // each segment is 4 bits, so 16 segments form 64 bits
#define VERTEX_DEGREE 5
#define NUM_OF_SUBKEYS 16
const uint8_t CLEBSCH_ADJACENCY_LIST[NUM_VERTICES][VERTEX_DEGREE];
// Subkey Generation Using the Graph
uint64_t generate_subkey_graph(uint64_t master_key, uint8_t round);
uint64_t* get_all_subkeys(uint64_t master_key);

#endif CLEBSCH_H