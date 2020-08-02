/*
* backend.h
*
*  Created on: Aug 25, 2017
*      Author: chiraag
*
*/

#ifndef LBCRYPTO_MATH_BACKEND_H
#define LBCRYPTO_MATH_BACKEND_H

#include <inttypes.h>
#include <complex>
#include <vector>

#include "bigint/BigIntegerLibrary.h"
#include <emmintrin.h>

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION __FILE__ ":" STRINGIZE(__LINE__)

// #define M_PI 3.14159265358979323846 // Pi constant with double precision

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {
	typedef int8_t si8;
	typedef uint8_t ui8;
	typedef int32_t si32;
	typedef uint32_t ui32;
	typedef int64_t si64;
	typedef uint64_t ui64;
	typedef __int128_t si128;
	typedef __uint128_t ui128;
	typedef __m128i block;

	typedef std::complex<double> cd;

	typedef std::vector<si32> sv32;
	typedef std::vector<ui32> uv32;
	typedef std::vector<si64> sv64;
	typedef std::vector<ui64> uv64;
	typedef std::vector<ui128> uv128;

	typedef BigUnsigned bui;
	typedef std::vector<bui> bigV;

	typedef std::vector<double> dv;
	typedef std::vector<cd> cv;

	/**
	* @brief Lists all modes for RLWE schemes, such as BGV and FV
	*/
	enum MODE {
		RLWE = 0,
		OPTIMIZED = 1
	};

} // namespace lbcrypto ends


#endif
