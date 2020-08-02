#include <iostream>
#include <random>

#include "Common/Defines.h"
#include "Common/Timer.h"
#include "Common/Log.h"

#include "Network/Channel.h"
#include "Network/Session.h"
#include "Network/IOService.h"
#include <pke/gazelle.h>
#include <utils/backend.h>

#include "math/bit_twiddle.h"

using namespace std;
using namespace lbcrypto;
using namespace osuCrypto;

uv64 compAddMod(const uv64& a, const uv64& b, const ui64 p) {
    assert(a.size() == b.size());
    uv64 result(a.size());
    for (size_t i = 0; i < a.size(); i++) result[i] = (a[i] + b[i]) % p;
    return result;
}

uv64 compMultMod(const uv64& a, const uv64& b, const ui64 p) {
    assert(a.size() == b.size());
    uv64 result(a.size());
    for (size_t i = 0; i < a.size(); i++) result[i] = (a[i] * b[i]) % p;
    return result;
}

int main(int argc, char** argv) {

    ui32 window_size = 3;
    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(1.0);
    FVParams test_params {
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        RLWE, std::make_shared<DiscreteGaussianGenerator>(dgg),
        window_size
    };
    // ui32 num_windows = 1 + floor(log2(test_params.q))/test_params.window_size;

    ui64 z = RootOfUnity(test_params.phim << 1, test_params.q);
    ui64 z_p = RootOfUnity(test_params.phim << 1, test_params.p);
    ftt_precompute(z, test_params.q, test_params.logn);
    ftt_precompute(z_p, test_params.p, test_params.logn);
    encoding_precompute(test_params.p, test_params.logn);
    precompute_automorph_index(test_params.phim);

    {  // powers_of_base test
        uv64 data1 = get_dug_vector(test_params.phim, test_params.q);
        uv64 data2 = get_dug_vector(test_params.phim, test_params.q);
        uv64 correct = comp_mult_mod_q(data1, data2, test_params);

        ui32 num_windows = 1 + floor(log2(test_params.q))/test_params.window_size;
        std::vector<uv64> data1Powers = powers_of_base(data1, test_params.window_size, num_windows, test_params.q);

        std::vector<uv64> data2Decomp = base_decompose(data2, test_params.window_size, num_windows);

        uv64 result(test_params.phim, 0);
        for (size_t i = 0; i < num_windows; i++) {
            result = comp_add_mod_q(result, comp_mult_mod_q(data1Powers[i], data2Decomp[i], test_params), test_params);
        }

        check_vec_eq(result, correct, "powers_of_base is wrong");
    }

    // block commonSeed = sysRandomSeed();
    // PRNG prng1(commonSeed);
    // PRNG prng2(commonSeed);
    // PRNG prng3(commonSeed);
    //
    // KeyPair kp1 = KeyGen(prng1, test_params);
    // KeyPair kp2 = KeyGen(prng2, test_params);
    // KeyPair kp3 = KeyGen(prng3, test_params);

    int numClients = 2;

    MPKeyPair kp1 = MPKeyGen(test_params);
    MPKeyPair kp2 = MPKeyGen(test_params);
    // MPKeyPair kp3 = MPKeyGen(test_params);

    std::vector<MPPublicKey> pks = {kp1.pk, kp2.pk};  // kp3.pk};
    PublicKey mpPK = MPPKGen(pks, test_params);
    SecretKey mpSK(test_params.phim); mpSK.s = comp_add_mod_q(kp1.sk.s, kp2.sk.s, test_params);
    // PublicKey mpPK = MPPKAdd(kp3.pk, MPPKAdd(kp1.pk, kp2.pk, test_params), test_params);
    // PublicKey mpPK = MPPKAdd(kp1.pk, kp2.pk, test_params);
    // assert(mpPK.a == comp_add_mod_q(kp1.pk.a, kp2.pk.a, test_params));
    // PublicKey mpPK = EvalAdd(kp1.pk, EvalAdd(kp2.pk, kp3.pk, test_params), test_params);

    uv64 data1(test_params.phim, 1);  //  = get_dug_vector(test_params.phim, 1000);
    uv64 data2(test_params.phim, 1);  //  = get_dug_vector(test_params.phim, 1000);
    // uv64 data3 = get_dug_vector(test_params.phim, 1000);
    // uv64 correct = compAddMod(data3, compAddMod(data1, data2, test_params.p), test_params.p);
    uv64 correct = compAddMod(data1, data2, test_params.p);
    uv64 pt1 = data1;  // packed_encode(data1, test_params.p, test_params.logn);
    uv64 pt2 = data2;  // packed_encode(data2, test_params.p, test_params.logn);
    // uv64 pt3 = packed_encode(data3, test_params.p, test_params.logn);
    Ciphertext ct1 = Encrypt(mpPK, pt1, test_params);
    Ciphertext ct2 = Encrypt(mpPK, pt2, test_params);
    // Ciphertext ct3 = Encrypt(mpPK, pt3, test_params);

    {
        uv64 data1Test = Decrypt(mpSK, ct1, test_params);
        check_vec_eq(data1, data1Test, "mp pk not created correctly");
    }

    Ciphertext ct = EvalAdd(ct1, ct2, test_params);
    // ct = EvalAdd(ct, ct3, test_params);

    uv64 decShare1 = DecryptShare(kp1.sk, ct, numClients, test_params);
    uv64 decShare2 = DecryptShare(kp2.sk, ct, numClients, test_params);
    // uv64 decShare3 = DecryptShare(kp3.sk, ct, numClients, test_params);
    // uv64 encodedResult = comp_add_mod_q(decShare3, comp_add_mod_q(decShare1, decShare2, test_params), test_params);
    uv64 encodedResult = comp_add_mod_q(decShare1, decShare2, test_params);
    uv64 result = MPDecryptFin(encodedResult, test_params);
    // uv64 result = packed_decode(encodedResult, test_params.p, test_params.logn);
    for (size_t i = 0; i < result.size(); i++) result[i] /= numClients;

    check_vec_eq(result, correct, "mp enc dec mismatch");
    std::cout << "Demo passed\n";

}
