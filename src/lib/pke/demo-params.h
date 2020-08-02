/**
@file demo-params.h  --  Define common parameters for all parties in the demo. Allow for common parameters to be easily changed.

Author: Leo de Castro
*/

#pragma once
#include "pke/multiparty.h"

using namespace lbcrypto;
using namespace std;

// ui32 window_size = 10;
// ui64 p = 10027009;  // opt::p
// DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);
// FVParams test_params {
//     false,
//     opt::q, p, opt::logn, opt::phim,
//     (opt::q/p),
//     RLWE, std::make_shared<DiscreteGaussianGenerator>(dgg),
//     window_size
// };
// ui32 num_windows = 1 + floor(log2(test_params.q))/test_params.window_size;
//
// ui64 z = opt::z;  // RootOfUnity(test_params.phim << 1, test_params.q);
// ui64 z_p = opt::z_p; // RootOfUnity(test_params.phim << 1, test_params.p);

FVParamsDCRT test_params = gen_fv_three_limb_fast_dcrt_params();

inline void precompute_params() {
    precompute_dcrt_params(test_params);
	// ftt_precompute(z, test_params.q, test_params.logn);
	// ftt_precompute(z_p, test_params.p, test_params.logn);
	// encoding_precompute(test_params.p, test_params.logn);
	// precompute_automorph_index(test_params.phim);
}

uv64 argToVec(char* argv, const uint32_t length = 0, const bool verbose = false);

FVCiphertextDCRT argsToCt(char** argv, const ui32 startInd);

void outputCt(const FVCiphertextDCRT& ct);
