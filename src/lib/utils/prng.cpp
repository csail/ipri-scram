/*
 * prng.cpp
 *
 *  Created on: Apr 22, 2018
 *      Author: chiraag
 */

#include <stdexcept>
#include "prng.h"

namespace lbcrypto {
	BlockPRNG::BlockPRNG(const block& seed, ui64 bufferSize)
		:
		mBytesIdx(0),
		mBlockIdx(0)
	{
		SetSeed(seed, bufferSize);
	}

	void BlockPRNG::SetSeed(const block& seed, ui64 bufferSize)
	{
		mAes.setKey(seed);
		mBlockIdx = 0;

		if (mBuffer.size() == 0)
		{
			mBuffer.resize(bufferSize);
			mBufferByteCapacity = (sizeof(block) * bufferSize);
		}


		refillBuffer();
	}

	ui8 BlockPRNG::getBit() { return get<bool>(); }

	const block BlockPRNG::getSeed() const
	{
		if(mBuffer.size())
			return mAes.mRoundKey[0];

		throw std::runtime_error("PRNG has not been keyed " LOCATION);
	}

	void BlockPRNG::refillBuffer()
	{
		if (mBuffer.size() == 0)
			throw std::runtime_error("PRNG has not been keyed " LOCATION);

		mAes.ecbEncCounterMode(mBlockIdx, mBuffer.size(), mBuffer.data());
		mBlockIdx += mBuffer.size();
		mBytesIdx = 0;
	}

}
