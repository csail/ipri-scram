/*
 * distributiongenerator.h
 *
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */


#ifndef LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_

//used to define a thread-safe generator
#if defined (_MSC_VER)  // Visual studio
    //#define thread_local __declspec( thread )
#elif defined (__GCC__) // GCC
    #define thread_local __thread
#endif

#include "utils/backend.h"
#include "utils/prng.h"
#include <random>
#include "Common/Defines.h"

namespace lbcrypto {

	// Return a static generator object
	BlockPRNG &get_prng();
	// std::mt19937_64 &get_prng();

	uv64 get_bug_vector(const ui32 size);

	uv64 get_tug_vector(const ui32 size, const ui64 modulus);

	uv64 get_dug_vector(const ui32 size, const ui64 modulus);

	uv64 get_dug_vector_seeded(const ui32 size, const ui64 modulus, BlockPRNG& prng);

	uv64 get_dug_vector_opt(const ui32 size);

	uv64 get_dug_vector_seeded_opt(const ui32 size, BlockPRNG& prng);

	uv64 get_dgg_testvector(ui32 size, ui64 p, float std_dev = 40.0);

	/**
	* @brief Abstract class describing generator requirements.
	*
	* The Distribution Generator defines the methods that must be implemented by a real generator.
	* It also holds the single PRNG, which should be called by all child class when generating a random number is required.
	*
	*/

	// Base class for Distribution Generator by type
	class DistributionGenerator {
		public:
			DistributionGenerator () {}
			virtual ~DistributionGenerator() {}
	};

} // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
