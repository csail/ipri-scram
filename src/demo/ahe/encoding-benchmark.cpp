/*
Transform-Benchmarking: This code benchmarks the FTT code

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <pke/gazelle.h>
#include <iostream>
#include <cassert>
#include "utils/test.h"

using namespace lbcrypto;


int main() {
	std::cout << "Encoding Benchmark (ms):" << std::endl;

	//------------------ Setup Parameters ------------------
	ui64 z = RootOfUnity(opt::phim << 1, opt::q);
	ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
	ftt_precompute(z, opt::q, opt::logn);
	ftt_precompute(z_p, opt::p, opt::logn);
	encoding_precompute(opt::p, opt::logn);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

	FVParams slow_params {
		opt::q, opt::p, opt::logn, opt::phim,
		(opt::q/opt::p),
		OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
		20
	};

	FVParams test_params = slow_params;

	auto kp = KeyGen(test_params);

	ui32 num_cols_c=512;
	ui32 rows_per_ct = test_params.phim/num_cols_c;
	//std::vector<uv64> enc_p_mat(rows_per_ct, uv64(rows_per_ct));
	for(ui32 enc_col=0; enc_col<rows_per_ct; enc_col++){
		ui32 start = enc_col*num_cols_c;
		ui32 end = (enc_col+1)*num_cols_c;
		uv64 v(test_params.phim, 0);
		for(ui32 n=start; n<end; n++){
			v[n] = 1;
		}
		std::cout << "v : " << vec_to_str(v) << std::endl;

		uv64 pt = packed_encode(v, opt::p, opt::logn);
		std::cout << "pt: " << vec_to_str(pt) << std::endl;

		uv64 ct_null = NullEncrypt(pt, test_params);
		/*for(ui32 enc_row=0; enc_row<rows_per_ct; enc_row++){
			enc_p_mat[enc_row][enc_col] = pt[enc_row*test_params.phim/rows_per_ct];
		}*/
		std::cout << "ct: " << vec_to_str(ct_null) << std::endl << std::endl;
	}
	// std::cout << mat_to_str(enc_p_mat) << std::endl;

    return 0;
}
