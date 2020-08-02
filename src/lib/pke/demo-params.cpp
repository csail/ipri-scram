/**
@file demo_params.cpp  --  Implements common functions for demo scripts
*/

#include "pke/demo-params.h"

using namespace std;
using namespace lbcrypto;


uv64 argToVec(char* argv, const uint32_t length, const bool verbose) {
    uv64 result;
    uint32_t ind = 0;
    // for (size_t j = 0; j < test_params.phim; j++) {
    while (ind < strlen(argv)) {
        string currString = "";
        while (argv[ind] != ' ' && argv[ind] != '\n' && argv[ind] != '\0') {
            currString += argv[ind];
            if (verbose) std::cerr << currString << std::endl;
            ind++;
        }
        ind++;

        result.push_back(boost::lexical_cast<ui64>(currString));
    }

    if (length!=0) assert(result.size() == length);

    return result;
}

FVCiphertextDCRT argsToCt(char** argv, const ui32 startInd) {
    // std::cerr << "Loaded ct from " << startInd;
    FVCiphertextDCRT ct(test_params.phim, test_params.num_moduli);
    for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        ct.ciphVec[limb].a = argToVec(argv[startInd + limb]);
    for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        ct.ciphVec[limb].b = argToVec(argv[startInd + test_params.num_moduli + limb]);
    // std::cerr << " to " << startInd + 2*test_params.num_moduli << std::endl;
    return ct;
}

void outputCt(const FVCiphertextDCRT& ct) {
    for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        std::cout << vec_to_str(ct.ciphVec[limb].a) << std::endl;
    for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        std::cout << vec_to_str(ct.ciphVec[limb].b) << std::endl;
}
