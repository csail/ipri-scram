/**
@file combineShares.cpp  --  Part of IPRI demo. Takes in decryption shares and recombines them to form results.

Input format:
numResults
result1Share1
result1Share2
...
resultNShare(M-1)
resultNShareM

Output format:
result1
result2
result3
...
resultN

Author: Leo de Castro (ldec@mit.edu)
*/

#include "pke/demo-params.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char** argv) {

    int numResults = atoi(argv[1]);
    if ((argc - 2) % numResults != 0) throw std::logic_error("Wrong number of shares");

    int numClients = (argc - 2)/(test_params.num_moduli*numResults);

    // std::cerr << "Received " << argc << " arguments\n";
    // std::cerr << "Combining shares for " << numClients << " clients to produce " << numResults << " results\n";

    precompute_params();

    for (int resNum = 0; resNum < numResults; resNum++) {
        std::vector<uv64> toDecode(test_params.num_moduli);
        // std::cerr << "Starting new result\n";
        for (int clNum = 0; clNum < numClients; clNum++) {
            int argNum = resNum*numClients*test_params.num_moduli + clNum*test_params.num_moduli + 2;
            std::vector<uv64> toAdd(test_params.num_moduli);
            for (size_t limb = 0; limb < test_params.num_moduli; limb++) {
                // std::cerr << "Loading arg at ind " << argNum + limb << std::endl;
                toAdd[limb] = argToVec(argv[argNum + limb]);
            }

            if (clNum == 0) toDecode = toAdd;
            else
                for (size_t limb = 0; limb < test_params.num_moduli; limb++)
                    toDecode[limb] = comp_add_mod_q(toAdd[limb], toDecode[limb], test_params.paramVec[limb]);
        }

        uv64 combined = MPDecryptFin(toDecode, test_params);
        uv64 result = packed_decode(combined, test_params.p, test_params.logn);
        for (size_t i = 0; i < test_params.phim; i++) result[i] /= numClients;

        std::cout << vec_to_str(result) << std::endl;
    }

}
