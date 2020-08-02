/*
 * prng.h
 *
 *	PRNG based Peter Rindall's cryptoTools
 *  Created on: Apr 22, 2018
 *
 */

#ifndef SRC_LIB_UTILS_PRNG_H_NO_
#define SRC_LIB_UTILS_PRNG_H_NO_

#include <cstring>
#include "backend.h"
#include "aes.h"

#pragma GCC diagnostic ignored "-Wignored-attributes"

namespace lbcrypto {
	// A Peudorandom number generator implemented using AES-NI.
	class BlockPRNG
	{
	public:

		// default construct leaves the PRNG in an invalid state.
		// SetSeed(...) must be called before get(...)
		BlockPRNG() = default;

		// explicit constructor to initialize the PRNG with the
		// given seed and to buffer bufferSize number of AES block
		BlockPRNG(const block& seed, ui64 bufferSize = 256);

		// Set seed from a block and set the desired buffer size.
		void SetSeed(const block& b, ui64 bufferSize = 256);

		// Return the seed for this PRNG.
		const block getSeed() const;

		// Templated function that returns the a random element
		// of the given type T.
		// Required: T must be a POD type.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, T>
			get()
		{
			T ret;
			get((ui8*)&ret, sizeof(T));
			return ret;
		}

		// Templated function that fills the provided buffer
		// with random elements of the given type T.
		// Required: T must be a POD type.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			get(T* dest, ui64 length)
		{
			ui64 lengthu8 = length * sizeof(T);
			ui8* destu8 = (ui8*)dest;
			while (lengthu8)
			{
				ui64 step = std::min(lengthu8, mBufferByteCapacity - mBytesIdx);

				memcpy(destu8, ((ui8*)mBuffer.data()) + mBytesIdx, step);

				destu8 += step;
				lengthu8 -= step;
				mBytesIdx += step;

				if (mBytesIdx == mBufferByteCapacity)
					refillBuffer();
			}
		}

		// Templated function that fills the provided buffer
		// with random elements of the given type T.
		// Required: T must be a POD type.
		// template<typename T>
		/* Not supporting span to avoid need for GSL
		typename std::enable_if_t<std::is_pod<T>::value, void>
			get(span<T> dest)
		{
			get(dest.data(), dest.size());
		}
		*/

		// Returns a random element from {0,1}
		ui8 getBit();

		// STL random number interface
		typedef ui32 result_type;
		// static result_type min() { return 0; }
		static constexpr result_type min() { return 0; }
		// static result_type max() { return (result_type)-1; }
		static constexpr result_type max() { return -1; }
		result_type operator()() {
			return get<result_type>();
		}
		result_type operator()(int mod) {
			return get<result_type>() % mod;
		}

		// internal buffer to store future random values.
		std::vector<block> mBuffer;

		// AES that generates the randomness by computing AES_seed({0,1,2,...})
		AES mAes;

		// Indicators denoting the current state of the buffer.
		ui64 mBytesIdx = 0,
			mBlockIdx = 0,
			mBufferByteCapacity = 0;

		// refills the internal buffer with fresh randomness
		void refillBuffer();
	};

	// specialization to make bool work correctly.
	template<>
	inline void BlockPRNG::get<bool>(bool* dest, ui64 length)
	{
		get((ui8*)dest, length);
		for (ui64 i = 0; i < length; ++i) dest[i] = ((ui8*)dest)[i] & 1;
	}

	// specialization to make bool work correctly.
	template<>
	inline bool BlockPRNG::get<bool>()
	{
		ui8 ret;
		get((ui8*)&ret, 1);
		return ret & 1;
	}

}

#endif /* SRC_LIB_UTILS_PRNG_H_NO_ */
