/**
@file decrypt.cpp  --  Part of the ipri demo. Decrypts the input ciphertexts with the input key.

Input Format:
numClients
sk
ct1.a
ct1.b
...
ctn.a
ctn.b

Output Format:
resultShare1
resultShare2
...
resultSharen

Author: Leo de Castro
*/

#include "pke/demo-params.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char** argv) {

    if ((argc & 1) != 1) throw std::logic_error("Wrong parity of arguments!");
    if (argc < 5) throw std::logic_error("Not enough arguments!");

    // std::cerr << "Received " << argc << " args\n";

    precompute_params();

    std::vector<SecretKey> sks(test_params.num_moduli, SecretKey(test_params.phim));

    int numClients = atoi(argv[1]);

    for (size_t i = 0; i < sks.size(); i++)
        sks[i].s = argToVec(argv[2 + i]);

    int numCts = (argc - (2 + sks.size()))/(2*sks.size());
    // std::cerr << "Decrypting " << numCts << " ciphertexts\n";
    std::vector<std::vector<uv64>> shares(numCts);
    for (int ctNum = 0; ctNum < numCts; ctNum++) {

        int argNum = 2*ctNum*test_params.num_moduli + 2 + sks.size();
        FVCiphertextDCRT ct = argsToCt(argv, argNum);

        // for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        //     ct.ciphVec[limb].a = argToVec(argv[argNum + ]);
        //
        // for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        //     ct.ciphVec[limb].b = argToVec(argv[2*ctNum*test_params.num_moduli + 2 + sks.size() + test_params.num_moduli + limb*test_params.num_moduli]);

        shares[ctNum] = DecryptShare(sks, ct, numClients, test_params);
    }

    for (int ctNum = 0; ctNum < numCts; ctNum++)
        for (size_t limb = 0; limb < test_params.num_moduli; limb++)
            std::cout << vec_to_str(shares[ctNum][limb]) << std::endl;

}
