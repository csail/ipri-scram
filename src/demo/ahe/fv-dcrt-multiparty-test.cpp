/**
@file fv-dcrt-multiparty-test.cpp  --  Tests dcrt multiparty functionality
*/

#include "pke/demo-params.h"
#include "utils/test.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char** argv) {

    precompute_params();
    ui32 numLimbs = test_params.num_moduli;

    block seed = sysRandomSeed();

    PRNG prng1(seed);
    PRNG prng2(seed);

    KeyPairDCRT kp1 = KeyGen(prng1, test_params);
    KeyPairDCRT kp2 = KeyGen(prng2, test_params);
    for (size_t i = 0; i < numLimbs; i++) {
        check_vec_eq(kp1.pk[i].a, kp2.pk[i].a, "Keygen mismatch");
    }

    std::vector<PublicKey> mpPK = MPPKAdd(kp1.pk, kp2.pk, test_params);
    for (size_t i = 0; i < numLimbs; i++) {
        check_vec_eq(kp1.pk[i].a, mpPK[i].a, "MPPKAdd mismatch");
    }

    uv64 data1(test_params.phim, 0);
    uv64 data2(test_params.phim, 0);
    data1[0] = 10;
    data2[0] = 20;
    data1 = packed_encode(data1, test_params.p, test_params.logn);
    data2 = packed_encode(data2, test_params.p, test_params.logn);

    FVCiphertextDCRT ct1 = Encrypt(mpPK, data1, test_params);
    FVCiphertextDCRT ct2 = Encrypt(mpPK, data2, test_params);

    FVCiphertextDCRT encRes = EvalAdd(ct1, ct2, test_params);

    std::vector<uv64> share1 = DecryptShare(kp1.sk, encRes, 2, test_params);
    std::vector<uv64> share2 = DecryptShare(kp2.sk, encRes, 2, test_params);

    std::vector<uv64> toDec(numLimbs);
    for (size_t i = 0; i < numLimbs; i++) {
        toDec[i] = comp_add_mod_q(share1[i], share2[i], test_params.paramVec[i]);
    }

    uv64 combined = MPDecryptFin(toDec, test_params);
    uv64 result = packed_decode(combined, test_params.p, test_params.logn);
    for (size_t i = 0; i < test_params.phim; i++) result[i] /= 2;

    std::cout << result[0] << std::endl;
}
