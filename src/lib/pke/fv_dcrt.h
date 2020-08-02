/*
 * fv_dcrt.h
 *
 *  Created on: Apr 20, 2018
 *      Author: leo
 *
 */


/**
Copied from fv.h to not break what Chiraag has elsewhere.
*/

#ifndef LBCRYPTO_CRYPTO_FV_DCRT_H
#define LBCRYPTO_CRYPTO_FV_DCRT_H

#include <memory>
using std::shared_ptr;

#include "../utils/backend.h"
#include "math/transfrm.h"
#include "pke_types.h"
#include "fv.h"
#include "pke/encoding.h"
#include "math/automorph.h"

namespace lbcrypto {

	/**
 	* @brief This is the parameters class for the FV encryption scheme.
 	*
 	* The FV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.
 	Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* @tparam Element a ring element type.
 	*/
	struct FVParamsDCRT {
		bui q;
		ui64 p;
		ui32 logn, phim;

		bui big_delta;
		double std_dev;

		ui32 num_moduli;  // The number of prime factors of the ct modulus
		uv64 p_i;  // prime factors of the ciphertext modulus
		bigV nb_i;  // product mod q of n_i (product of p_j for all i neq j) and b_i (inverse of n_i mod p_i)
		uv64 round_coeffs;  // product mod q[2] of n_i (product of p_j for all i neq j) and b_i (inverse of n_i mod p_i)
		ui64 q2_delta;

		std::vector<FVParams> paramVec;
	};

/**
DCRT ops
*/
	FVParamsDCRT gen_fv_test_dcrt_params();

	KeyPairDCRT KeyGen(const FVParamsDCRT& params);
	KeyPairDCRT KeyGen(osuCrypto::PRNG& prng, FVParamsDCRT& params);

	std::vector<PublicKey> MPPKAdd(const std::vector<PublicKey>& pk1, const std::vector<PublicKey>& pk2, const FVParamsDCRT& params);

	std::vector<uv64> NullEncrypt(uv64& pt, const FVParamsDCRT& params);
	std::vector<uv64> NullEncryptDelta(uv64& pt, const FVParamsDCRT& params);

	FVCiphertextDCRT Encrypt(const std::vector<SecretKey>& sk, uv64& pt, const FVParamsDCRT& params);
	FVCiphertextDCRT Encrypt(const std::vector<PublicKey>& pk, uv64& pt, const FVParamsDCRT& params);

	Ciphertext RoundDCRT(const FVCiphertextDCRT& ct, const FVParamsDCRT& params);

	uv64 Decrypt(const std::vector<SecretKey>& skL, const FVCiphertextDCRT& ct, const FVParamsDCRT& params);
	uv64 DecryptRounded(const SecretKey& sk, const Ciphertext& ct, const FVParamsDCRT& params);

	std::vector<uv64> DecryptShare(const std::vector<SecretKey>& skL, const FVCiphertextDCRT& ct, const ui32 numClients, const FVParamsDCRT& params);
	uv64 MPDecryptFin(const std::vector<uv64>& toScaleDown, const FVParamsDCRT& params);

	sv64 NoiseRounded(const SecretKey& sk, const Ciphertext& ct, const FVParamsDCRT& params);

	double NoiseMarginRounded(const SecretKey& sk, const Ciphertext& ct, const FVParamsDCRT& params);

	// Ciphertext reference_Round(const FVCiphertextDCRT& ct, FVParamsDCRT& params); // DEBUG

	FVCiphertextDCRT EvalAdd(const FVCiphertextDCRT& ct1, const FVCiphertextDCRT& ct2, const FVParamsDCRT& params);
	FVCiphertextDCRT EvalAddPlain(const FVCiphertextDCRT& ct, const std::vector<uv64>& pt, const FVParamsDCRT& params);

	FVCiphertextDCRT EvalSub(const FVCiphertextDCRT& ct1, const FVCiphertextDCRT& ct2, const FVParamsDCRT& params);
	FVCiphertextDCRT EvalSubPlain(const FVCiphertextDCRT& ct, const std::vector<uv64>& pt, const FVParamsDCRT& params);

	FVCiphertextDCRT EvalMultPlain(const FVCiphertextDCRT& ct, const std::vector<uv64>& pt, const FVParamsDCRT& params);

	FVCiphertextDCRT EvalNegate(const FVCiphertextDCRT& ct, const FVParamsDCRT& params);

	// FVCiphertextDCRT AddRandomNoise(const std::vector<PublicKey> pk, const FVCiphertextDCRT& ct, const FVParamsDCRT& params);

/**
Other useful ops
*/

	bigV dcrt_to_bigVec(const std::vector<uv64>& mod_vecs, const FVParamsDCRT& params);

	uv64 sample_error(const FVParams& params);

	std::vector<uv64> sample_error_dcrt(const FVParamsDCRT& params);

	uv64 sample_random_vec_q(const FVParams& params);

	uv64 sample_random_plaintext_data(const FVParams& params);

	uv64 sample_random_plaintext_data_fv(const ui64 phim, ui64 p);

	uv64 comp_neg_mod_q(const uv64& a, const FVParams& params);

} // namespace lbcrypto ends
#endif
