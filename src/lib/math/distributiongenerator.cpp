/*
 * distributiongenerator.cpp
 *
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */
 
#include "distributiongenerator.h"
#include "math/params.h"
#include "utils/prng.h"
#include <random>

namespace lbcrypto {
	BlockPRNG& get_prng(){
		// C++11 thread-safe static initialization
		// static thread_local std::mt19937_64 prng(std::random_device{}());
		// static thread_local BlockPRNG prng(_mm_setzero_si128(), 256);
		static thread_local BlockPRNG prng(osuCrypto::sysRandomSeed(), 256);
		return prng;
	}

	/* std::mt19937_64& get_prng(){
		// C++11 thread-safe static initialization
		static thread_local std::mt19937_64 prng(std::random_device{}());
		return prng;
	}*/

	uv64 get_bug_vector (const ui32 size) {
		auto prng = get_prng();
		auto distribution = std::uniform_int_distribution<ui64>(0, 1);

		uv64 v(size);
		for (ui32 i = 0; i < size; i++) {
			v[i] = distribution(prng);
		}
		return v;
	}

	uv64 get_tug_vector (const ui32 size, const ui64 modulus) {
		auto prng = get_prng();
		auto distribution = std::uniform_int_distribution<si32>(-1,1);
		ui64 minus1 = modulus - 1;
		uv64 v(size);

		for(ui32 m=0; m<size; m++){
			si32 rand = distribution(prng);
			switch(rand){
			case -1:
				v[m] = minus1; break;
			case 0:
				v[m] = 0; break;
			case 1:
				v[m] = 1; break;
			}

		}

		return v;
	}

	uv64 get_dug_vector(const ui32 size, const ui64 modulus) {
		auto prng = get_prng();
		auto distribution = std::uniform_int_distribution<ui64>(0, modulus-1);

		uv64 v(size);

		for (ui32 i = 0; i < size; i++) {
			v[i] = distribution(prng);
		}
		return v;
	}

	uv64 get_dug_vector_seeded(const ui32 size, const ui64 modulus, BlockPRNG& prng) {
		auto distribution = std::uniform_int_distribution<ui64>(0, modulus-1);

		uv64 v(size);

		for (ui32 i = 0; i < size; i++) {
			v[i] = distribution(prng);
		}
		return v;
	}

	uv64 get_dug_vector_opt(const ui32 size) {
		auto prng = get_prng();
		ui64 max = ((opt::q) << 4);

		uv64 v(size);

		for (ui32 i = 0; i < size;) {
			ui64 rand = prng();
			if(rand < max){
				v[i] = opt::modq_full(rand);
				i++;
			}
		}
		return v;
	}

	uv64 get_dug_vector_seeded_opt(const ui32 size, BlockPRNG& prng) {
		ui64 max = ((opt::q) << 4);

		uv64 v(size);

		for (ui32 i = 0; i < size;) {
			ui64 rand = prng();
			if(rand < max){
				v[i] = opt::modq_full(rand);
				i++;
			}
		}
		return v;
	}

	uv64 get_dgg_testvector(ui32 size, ui64 p, float std_dev){
		std::normal_distribution<double> distribution(0,std_dev);
		auto& prng = get_prng();

		uv64 vec(size);
		for(ui32 i=0; i<size; i++){
			si32 r = std::max(-127, std::min(128, (si32)distribution(prng)));
			vec[i] = (r>=0)? r : p+r;
		}
		return vec;
	}



} // namespace lbcrypto
