/*
 * pke_types.h
 *
 *	Barebones data-structures
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#ifndef LBCRYPTO_CRYPTO_PUBKEYLP_H
#define LBCRYPTO_CRYPTO_PUBKEYLP_H

#include <vector>
#include "math/distrgen.h"


namespace lbcrypto {
	struct Ciphertext {
		uv64 a;
		uv64 b;

		Ciphertext() {};  // used to initialize vectors

		Ciphertext(ui32 size) : a(size), b(size) {};
	};

	struct FVCiphertextDCRT {
		std::vector<Ciphertext> ciphVec;

		FVCiphertextDCRT() {};  // used to initialize other classes

		FVCiphertextDCRT(ui32 size, ui32 num_moduli) : ciphVec(num_moduli) {
			for (ui32 i = 0; i < num_moduli; i++) {
				ciphVec[i] = Ciphertext(size);
			}
		};
	};

	/**
	 * @brief Concrete class for LP public keys
	 * @tparam Element a ring element.
	 */
	struct PublicKey {
		uv64 a;
		uv64 b;

		PublicKey() : a(0), b(0) {};  // used to initialize vectors
		PublicKey(ui32 size) : a(size), b(size) {};
	};

	/**
	* @brief Concrete class for Relinearization keys of RLWE scheme
	* @tparam Element a ring element.
	*/
	struct RelinKey {
		std::vector<uv64> a;
		std::vector<uv64> b;

		RelinKey(ui32 size, ui32 windows) : a(windows, uv64(size)), b(windows, uv64(size)) {};
	};


	/**
	* @brief Private key implementation template for Ring-LWE, NTRU-based schemes,
	* @tparam Element a ring element.
	*/
	struct SecretKey {
		uv64 s;

		SecretKey() : s(0) {};  // used to initialize vectors
		SecretKey(ui32 size) : s(size) {};
	};

	struct KeyPair {
	public:
		PublicKey pk;
		SecretKey sk;

		KeyPair(const PublicKey& pk, const SecretKey& sk) : pk(pk),	sk(sk) {};
	};

	struct MPPublicKey {
		uv64 a;
		std::vector<uv64> b;

		MPPublicKey(const uv64& a, const std::vector<uv64>& b) : a(a), b(b) {};
	};

	struct MPKeyPair {
	public:
		MPPublicKey pk;
		SecretKey sk;

		MPKeyPair(const MPPublicKey& pk, const SecretKey& sk) : pk(pk), sk(sk) {};
	};

    struct KeyPairDCRT {
    public:
        std::vector<PublicKey> pk;
        std::vector<SecretKey> sk;

        KeyPairDCRT() {}; // used to initialize class

        KeyPairDCRT(const ui32 num_moduli, const ui32 size) : pk(num_moduli), sk(num_moduli) {
        	for (ui32 i = 0; i < num_moduli; i++) {
        		pk[i] = PublicKey(size);
        		sk[i] = SecretKey(size);
        	}
        };
    };

} // namespace lbcrypto ends
#endif
