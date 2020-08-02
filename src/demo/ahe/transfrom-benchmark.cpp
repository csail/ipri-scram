/*
Transform-Benchmarking: This code benchmarks the FTT code

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <utils/backend.h>
#include <iostream>
#include <cassert>
#include "utils/debug.h"
#include "utils/test.h"
#include "math/params.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "math/transfrm.h"

using namespace lbcrypto;


int main() {
	std::cout << "Transform Benchmark (ms):" << std::endl;

	//------------------ Setup Parameters ------------------
	ui64 nRep;
	double start, stop;

	uv64 x = get_dug_vector(opt::phim, opt::q);
	uv64 X, xx;

	ui64 z = RootOfUnity(opt::phim << 1, opt::q);
	ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
	ftt_precompute(z, opt::q, opt::logn);
	ftt_precompute(z_p, opt::p, opt::logn);
	X = ftt_fwd(x, opt::q, opt::logn);
	xx = ftt_inv(X, opt::q, opt::logn);


	ui64 t = opt::mul_modq_part(opt::q-1, opt::q-1);
	std::cout << opt::q-1 << " " << opt::modq_full(t) << std::endl;


	check_vec_eq(x, xx, "ftt mismatch\n");

	//-------------------- Baseline FTT --------------------
	nRep = 1000;
	start = currentDateTime();
	for(uint64_t n=0; n<nRep; n++){
		X = ftt_fwd(x, opt::q, opt::logn);
	}
	stop = currentDateTime();
	std::cout << " ftt_fwd: " << (stop-start)/nRep << std::endl;

	return 0;
}
