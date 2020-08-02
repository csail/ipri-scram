/**
@file runDemo.cpp  --  Part of the ipri demo. This file is run by the server to compute on the encryped clients' inputs.

Input Format:
ct1.a
ct1.b
ct2.a
ct2.b
...
ctn.a
ctn.b

Output Format:
result1.a
result1.b
...
resultm.a
resultm.b

The current computation is to simply sum up the input ciphertexts.

Author: Leo de Castro (ldec@mit.edu)
*/

#include "pke/multiparty.h"
#include "pke/demo-params.h"

using namespace std;
using namespace lbcrypto;
using namespace osuCrypto;

int main(int argc, char** argv) {
    if ((argc & 1) != 1)
        throw std::logic_error("Cannot parse an odd number of arguments");

    int numCts = (argc - 1)/(2*test_params.num_moduli);
    // std::cerr << "Num args: " << argc << std::endl;
    // std::cerr << "Num cts: " << numCts << std::endl;

    precompute_params();

    // std::cerr << "Precomputed params\n";

    // Load cts and add them up.
    FVCiphertextDCRT result(test_params.phim, test_params.num_moduli);
    FVCiphertextDCRT result_sq(test_params.phim, test_params.num_moduli);
    for (int ctNum = 0; ctNum < numCts; ctNum++) {
        // FVCiphertextDCRT ct(test_params.num_moduli);
        // for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        //     ct.ctVec[limb].a = argToVec(argv[2*ctNum + 1 + limb]);
        // for (size_t limb = 0; limb < test_params.num_moduli; limb++)
        //     ct.ctVec[limb].b = argToVec(argv[2*ctNum + 2 + ]);

        // std::cerr << "Loading ct at argNum " << 2*(test_params.num_moduli)*ctNum + 1 << std::endl;
        FVCiphertextDCRT ct = argsToCt(argv, 2*(test_params.num_moduli)*ctNum + 1);
        // std::cerr << "Loaded regular ct\n";

        if (ctNum == 0) result = ct;
        else result = EvalAdd(ct, result, test_params);
        // std::cerr << "Added cts\n";

        ctNum++;

        // std::cerr << "Loading ct at argNum " << 2*(test_params.num_moduli)*ctNum + 1 << std::endl;
        FVCiphertextDCRT ct_sq = argsToCt(argv, 2*(test_params.num_moduli)*ctNum + 1);
        // std::cerr << "Loaded sq ct\n";

        // Ciphertext ct_sq(test_params.phim);
        // ct_sq.a = argToVec(argv[2*ctNum + 1]);
        // ct_sq.b = argToVec(argv[2*ctNum + 2]);

        if (ctNum == 1) result_sq = ct_sq;
        else result_sq = EvalAdd(ct_sq, result_sq, test_params);
        // std::cerr << "Added sq cts\n";
    }

    outputCt(result);
    outputCt(result_sq);

    // std::cout << vec_to_str(result.a) << std::endl;
    // std::cout << vec_to_str(result.b) << std::endl;
    // std::cout << vec_to_str(result_sq.a) << std::endl;
    // std::cout << vec_to_str(result_sq.b) << std::endl;
}
