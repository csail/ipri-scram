/**
@file generateSeed.cpp  --  Run by the server in the ipri demo to generate a seed for the a generation.

Designed to be called from the py-demo server. Returns the key to the server via stdout.

Author: Leo de Castro
*/

#include "pke/multiparty.h"

using namespace lbcrypto;
using namespace osuCrypto;

int main(int argc, char** argv) {
    block seed = sysRandomSeed();
    ui64 top = _mm_extract_epi64(seed, 0);
    ui64 bottom = _mm_extract_epi64(seed, 1);
    std::cout << top << std::endl;
    std::cout << bottom << std::endl;
}

