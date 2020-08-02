/**
@file keyGen.cpp  --  Part of the ipri demo. Run by the client to generate an HE keypair.

Expects the following command-line arguments:
(prng seed top half) (prng seed bottom half)

Returns the key to the client server in the following format:
sk
pk.a
pk.b

Author: Leo de Castro
*/

#include "pke/multiparty.h"
#include "pke/demo-params.h"

using namespace std;
using namespace lbcrypto;
using namespace osuCrypto;

int main (int argc, char** argv) {
    // std::cerr << "Starting keygen...\n";
    if (argc != 3) throw std::logic_error("Expects 2 prng seed halves as arguments");

    ui64 top = atoi(argv[1]);
    ui64 bottom = atoi(argv[2]);
    auto seed = _mm_set_epi64x(top, bottom);

    precompute_params();

    PRNG prng(seed);

    // std::cerr << "Starting KeyGen()...\n";
    KeyPairDCRT kp = KeyGen(prng, test_params);
    // std::cerr << "Finished with keygen\n";
    for (size_t i = 0; i<test_params.num_moduli; i++)
        std::cout << vec_to_str(kp.sk[i].s) << std::endl;
    for (size_t i = 0; i<test_params.num_moduli; i++)
        std::cout << vec_to_str(kp.pk[i].a) << std::endl;
    for (size_t i = 0; i<test_params.num_moduli; i++)
        std::cout << vec_to_str(kp.pk[i].b) << std::endl;
}
