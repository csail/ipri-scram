/**
@file encryptVector.cpp  --  Part of the IPRI demo. Encrypts data from a CSV file using the input public key.

NOTE: Number of CSV entries MUST not exceed the number of ciphertext slots. See demo_params.h for the number of slots.

Input Format:
data to encrypt
pka
pkb

Output Format:
cta
ctb

Author: Leo de Castro
*/

#include "pke/demo-params.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char** argv) {

    // std::cerr << "Starting encryptVec\n";

    // if (argc != 2 + 2*test_params.num_moduli) throw std::logic_error("Invalid number of arguments");

    // std::cerr << "Veriefied number of arguments";

    precompute_params();

    // Load data to encrypt
    uv64 data = argToVec(argv[1]);
    uv64 data_sq(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        data_sq[i] = data[i]*data[i];
    }

    // std::cerr << "Loaded data\n";

    // Load Public Key
    std::vector<PublicKey> pks(test_params.num_moduli, PublicKey(test_params.phim));
    for (size_t i = 0; i < pks.size(); i++) {
        pks[i].a = argToVec(argv[2 + i]);
    }
    for (size_t i = 0; i < pks.size(); i++) {
        pks[i].b = argToVec(argv[2 + i + test_params.num_moduli]);
    }

    // std::cerr << "Loaded pk\n";

    // Encrypt
    uv64 pt = packed_encode(data, test_params.p, test_params.logn);
    FVCiphertextDCRT ct = Encrypt(pks, pt, test_params);

    uv64 pt_sq = packed_encode(data_sq, test_params.p, test_params.logn);
    FVCiphertextDCRT ct_sq = Encrypt(pks, pt_sq, test_params);

    outputCt(ct);
    outputCt(ct_sq);
}
