/**
@file generateSharedKey.cpp  --  Takes in public keys as arguments and prints out the agregated public key.

Arguments are accepted in the following order
Public key 1.a
Public key 1.b
Public key 2.a
...

Outputs are in the following format:
mpPK.a
mpPK.b

Author: Leo de Castro
*/

// #include "pke/multiparty.h"
#include "pke/demo-params.h"

using namespace std;
using namespace lbcrypto;
using namespace osuCrypto;

int main(int argc, char** argv) {

    if ((argc & 1) != 1)
        throw std::logic_error("Cannot parse an odd number of arguments");

    int numKeys = (argc - 1)/(2*test_params.num_moduli);

    precompute_params();

    std::vector<PublicKey> mpPK(test_params.phim);

    for (int i = 0; i < numKeys; i++) {
        std::vector<PublicKey> clientPK(test_params.num_moduli, PublicKey(test_params.phim));

        int arg_num = 2*(test_params.num_moduli)*i + 1;
        for (size_t limb = 0; limb < test_params.num_moduli; limb++) {
            clientPK[limb].a = argToVec(argv[arg_num + limb]);
            // std::cerr << "PKa: " << vec_to_str(clientPK[limb].a) << std::endl;
        }
        for (size_t limb = 0; limb < test_params.num_moduli; limb++) {
            clientPK[limb].b = argToVec(argv[arg_num + limb + test_params.num_moduli]);
            // std::cerr << "PKb: " << vec_to_str(clientPK[limb].b) << std::endl;
        }

        if (i == 0) mpPK = clientPK;
        else mpPK = MPPKAdd(mpPK, clientPK, test_params);
    }

    for (size_t limb = 0; limb < test_params.num_moduli; limb++) {
        std::cout << vec_to_str(mpPK[limb].a) << std::endl;
    }
    for (size_t limb = 0; limb < test_params.num_moduli; limb++) {
        std::cout << vec_to_str(mpPK[limb].b) << std::endl;
    }
}
