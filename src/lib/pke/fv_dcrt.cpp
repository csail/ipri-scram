/*
 * fv_dcrt.cpp
 *
 *  Created on: Apr 20, 2018
 *      Author: leo
 *
 */


/**
Copied from fv.cpp to not break what Chiraag has elsewhere.
*/

#include <iostream>
#include <map>
#include <memory>
using std::shared_ptr;

#ifndef LBCRYPTO_CRYPTO_FV_DCRT_C
#define LBCRYPTO_CRYPTO_FV_DCRT_C

#include "math/params.h"
#include "math/transfrm.h"
#include "math/automorph.h"
#include "pke/encoding.h"
#include "pke/fv_dcrt.h"
#include "utils/test.h"


#include <iostream>

namespace lbcrypto {

/**
DCRT ops
*/

//
// KeyGen
//
	KeyPairDCRT KeyGen(const FVParamsDCRT& params) {
		KeyPairDCRT result(params.num_moduli, params.phim);
    	std::vector<uv64> dcrt_s = sample_error_dcrt(params);
    	std::vector<uv64> dcrt_e = sample_error_dcrt(params);

    	for (ui32 i = 0; i < params.num_moduli; i++) {
	        KeyPair kp = KeyGenLimb(dcrt_s[i], dcrt_e[i], params.paramVec[i]);
	        result.pk[i] = kp.pk;
	        result.sk[i] = kp.sk;
	    }

	    return result;
	}

	KeyPairDCRT KeyGen(osuCrypto::PRNG& prng, FVParamsDCRT& params) {
		KeyPairDCRT result(params.num_moduli, params.phim);
    	std::vector<uv64> dcrt_s = sample_error_dcrt(params);
    	std::vector<uv64> dcrt_e = sample_error_dcrt(params);

    	for (ui32 i = 0; i < params.num_moduli; i++) {
			std::cerr << "Starting KeyGenLimb()...\n";
	        KeyPair kp = KeyGenLimb(prng, dcrt_s[i], dcrt_e[i], params.paramVec[i]);
			std::cerr << "Finished KeyGenLimb\n";
	        result.pk[i] = kp.pk;
	        result.sk[i] = kp.sk;
	    }

	    return result;
	}

	std::vector<PublicKey> MPPKAdd(const std::vector<PublicKey>& pk1, const std::vector<PublicKey>& pk2, const FVParamsDCRT& params) {
		std::vector<PublicKey> result(params.num_moduli);
		for (size_t limb = 0; limb < params.num_moduli; limb++)
			result[limb] = MPPKAdd(pk1[limb], pk2[limb], params.paramVec[limb]);

		return result;
	}

//
// Encrypt
//

	std::vector<uv64> NullEncrypt(uv64& pt, const FVParamsDCRT& params) {
		std::vector<uv64> result(params.num_moduli, uv64(params.phim));
    	for (ui32 i = 0; i < params.num_moduli; i++) {
	        result[i] = NullEncrypt(pt, params.paramVec[i]);
	    }
	    return result;
	}


	std::vector<uv64> NullEncryptDelta(uv64& pt, const FVParamsDCRT& params) {
		std::vector<uv64> result(params.num_moduli, uv64(params.phim));
    	for (ui32 i = 0; i < params.num_moduli; i++) {
	        result[i] = NullEncryptDelta(pt, params.paramVec[i]);
	    }
	    return result;
	}

	FVCiphertextDCRT Encrypt(const std::vector<SecretKey>& sk, uv64& pt, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
    	std::vector<uv64> dcrt_err = sample_error_dcrt(params);
    	for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EncryptLimb(sk[i], pt, dcrt_err[i], params.paramVec[i]);
	    }
	    return result;
	}

	FVCiphertextDCRT Encrypt(const std::vector<PublicKey>& pk, uv64& pt, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
	    std::vector<uv64> dcrt_e = sample_error_dcrt(params);
	    std::vector<uv64> dcrt_u = sample_error_dcrt(params);
	    std::vector<uv64> dcrt_e_prime = sample_error_dcrt(params);
	    for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EncryptLimb(pk[i], pt, dcrt_e[i], dcrt_u[i], dcrt_e_prime[i], params.paramVec[i]);
	    }
	    return result;
	}

	uv64 Decrypt(const std::vector<SecretKey>& skL, const FVCiphertextDCRT& ct, const FVParamsDCRT& params) {
		std::vector<uv64> prod_mul(params.num_moduli);
		for (ui32 prm_ind = 0; prm_ind < params.num_moduli; prm_ind++) {
			uv64 mod_prod(params.phim);
			for (ui32 i = 0; i < params.phim; i++) {
				mod_prod[i] =
					(mod_mul(ct.ciphVec[prm_ind].a[i], skL[prm_ind].s[i], params.p_i[prm_ind])
						+ ct.ciphVec[prm_ind].b[i]) % params.p_i[prm_ind];
			}
			prod_mul[prm_ind] = ToCoeff(mod_prod, params.paramVec[prm_ind]);
		}
		bigV big_res = dcrt_to_bigVec(prod_mul, params);
		uv64 pt(params.phim);
		bui delta_by_2 = params.big_delta/2;
		for(ui32 i = 0; i < params.phim; i++){
			pt[i] = (((big_res[i] + delta_by_2)/params.big_delta) % params.p).toUnsignedLong();
		}

		return pt;
	}

	std::vector<uv64> DecryptShare(const std::vector<SecretKey>& skL, const FVCiphertextDCRT& ct, const ui32 numClients, const FVParamsDCRT& params) {
		std::vector<uv64> prod_mul(params.num_moduli);
		for (ui32 prm_ind = 0; prm_ind < params.num_moduli; prm_ind++) {
			uv64 mod_prod(params.phim);
			for (ui32 i = 0; i < params.phim; i++) {
				mod_prod[i] =
					(mod_mul(numClients, mod_mul(ct.ciphVec[prm_ind].a[i], skL[prm_ind].s[i], params.p_i[prm_ind]), params.p_i[prm_ind])
						+ ct.ciphVec[prm_ind].b[i]) % params.p_i[prm_ind];
			}
			prod_mul[prm_ind] = ToCoeff(mod_prod, params.paramVec[prm_ind]);
		}
		// TODO: Flood with noise
		return prod_mul;
	}

	uv64 MPDecryptFin(const std::vector<uv64>& toScaleDown, const FVParamsDCRT& params) {
		bigV big_res = dcrt_to_bigVec(toScaleDown, params);
		uv64 pt(params.phim);
		bui delta_by_2 = params.big_delta/2;
		for(ui32 i = 0; i < params.phim; i++){
			pt[i] = (((big_res[i] + delta_by_2)/params.big_delta) % params.p).toUnsignedLong();
		}

		return pt;
	}


	uv64 DecryptRounded(const SecretKey& sk, const Ciphertext& ct, const FVParamsDCRT& params){
		// Ciphertext comes in as
		//   (a*u + ea, -a*s*u - e*u + m*delta + eb)

		auto sz = params.p_i.size();

		uv64 pt(params.phim);
		for(ui32 i=0; i<params.phim; i++){
            pt[i] = mod_mul(ct.a[i], sk.s[i], params.p_i[sz-1]) + ct.b[i];
		}
		// pt has the form
		//   a*u*s + ea*s -a*s*u - e*u + m*delta + eb
		//  = ea*s - e*u + m*delta + eb
		//  = m * delta + small
		pt = ToCoeff(pt, params.paramVec[sz-1]);

		auto delta_by_2 = params.q2_delta/2;
		for(ui32 i=0; i<params.phim; i++){
			pt[i] = (pt[i] + delta_by_2)/params.q2_delta;
		}

		return pt;
	};


	sv64 NoiseRounded(const SecretKey& sk, const Ciphertext& ct, const FVParamsDCRT& params){
		auto sz = params.num_moduli;

		uv64 e(params.phim);
		for(ui32 i=0; i<params.phim; i++){
			e[i] = mod_mul(ct.a[i], sk.s[i], params.p_i[sz-1]) + ct.b[i];
		}
		e = ToCoeff(e, params.paramVec[sz-1]);

		sv64 es(params.phim);
		auto delta_by_2 = params.q2_delta/2;
		for(ui32 i=0; i<params.phim; i++){
			e[i] = (e[i] % params.q2_delta);
			es[i] = (e[i] > delta_by_2) ? (e[i] - params.q2_delta) : e[i];
		}

		return es;
	};

	double NoiseMarginRounded(const SecretKey& sk, const Ciphertext& ct, const FVParamsDCRT& params){
		sv64 noise = NoiseRounded(sk, ct, params);

		ui64 noise_max = 0;
		for(uint32_t i=0; i<params.phim; i++){
			ui64 noise_abs = std::abs(noise[i]);
			noise_max = std::max(noise_max, noise_abs);
		}

		return (std::log2(params.q2_delta)-std::log2(noise_max));
	}

	Ciphertext RoundDCRT(const FVCiphertextDCRT& ct, const FVParamsDCRT& params) {
		// First, get all ciphertexts to coeff
		FVCiphertextDCRT coeff(params.phim, params.num_moduli);
		for (ui32 i = 0; i < params.num_moduli; i++) {
			coeff.ciphVec[i].a = ToCoeff(ct.ciphVec[i].a, params.paramVec[i]);
			coeff.ciphVec[i].b = ToCoeff(ct.ciphVec[i].b, params.paramVec[i]);
		}

		Ciphertext result(params.phim);
		for (ui32 mod_ind = 0; mod_ind < params.num_moduli; mod_ind++) {
			for (ui32 vec_ind = 0; vec_ind < params.phim; vec_ind++) {
				result.a[vec_ind] = mod(result.a[vec_ind] + mod_mul(params.round_coeffs[mod_ind],
					coeff.ciphVec[mod_ind].a[vec_ind], params.p_i[params.num_moduli-1]), params.p_i[params.num_moduli-1]);

				result.b[vec_ind] = mod(result.b[vec_ind] + mod_mul(params.round_coeffs[mod_ind],
					coeff.ciphVec[mod_ind].b[vec_ind], params.p_i[params.num_moduli-1]), params.p_i[params.num_moduli-1]);
			}
		}

//		 std::vector<uv64> test_vec = {{283718018218352675}, {1102492646205470429}, {1838145795429317034}};
//		 ui64 test_res = 0;
//		 for (ui32 mod_ind = 0; mod_ind < params.num_moduli; mod_ind++) {
//		 	test_res = (test_res + mod_mul(test_vec[mod_ind][0], params.round_coeffs[mod_ind], params.p_i[2])) % params.p_i[2];
//		 }
//		 std::cout << "test result: " << test_res << std::endl;

		result.a = ToEval(result.a, params.paramVec[params.num_moduli - 1]);
		result.b = ToEval(result.b, params.paramVec[params.num_moduli - 1]);

	    return result;
	}

//
// Ops
//

	FVCiphertextDCRT EvalAdd(const FVCiphertextDCRT& ct1, const FVCiphertextDCRT& ct2, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
	    for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EvalAdd(ct1.ciphVec[i], ct2.ciphVec[i], params.paramVec[i]);
	    }
	    return result;
	}

	FVCiphertextDCRT EvalAddPlain(const FVCiphertextDCRT& ct, const std::vector<uv64>& pt, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
	    for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EvalAddPlain(ct.ciphVec[i], pt[i], params.paramVec[i]);
	    }
	    return result;
	}

	FVCiphertextDCRT EvalSub(const FVCiphertextDCRT& ct1, const FVCiphertextDCRT& ct2, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
	    for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EvalSub(ct1.ciphVec[i], ct2.ciphVec[i], params.paramVec[i]);
	    }
	    return result;
	}

	FVCiphertextDCRT EvalSubPlain(const FVCiphertextDCRT& ct, const std::vector<uv64>& pt, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
	    for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EvalSubPlain(ct.ciphVec[i], pt[i], params.paramVec[i]);
	    }
	    return result;
	}

	FVCiphertextDCRT EvalMultPlain(const FVCiphertextDCRT& ct, const std::vector<uv64>& pt, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
	    for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EvalMultPlain(ct.ciphVec[i], pt[i], params.paramVec[i]);
	    }
	    return result;
	}

	FVCiphertextDCRT EvalNegate(const FVCiphertextDCRT& ct, const FVParamsDCRT& params) {
		FVCiphertextDCRT result(params.phim, params.num_moduli);
	    for (ui32 i = 0; i < params.num_moduli; i++) {
	        result.ciphVec[i] = EvalNegate(ct.ciphVec[i], params.paramVec[i]);
	    }
	    return result;
	}


/**
Other useful ops
*/

bigV dcrt_to_bigVec(const std::vector<uv64>& mod_vecs, const FVParamsDCRT& params) {
    // Assumes each vector has length params.phim
    bigV result(params.phim);
    std::vector<bool> first_entry(params.phim);
    for (ui32 i = 0; i < params.phim; i++) { first_entry[i] = true; }

    for (ui32 i = 0; i < params.num_moduli; i++) {
        for (ui32 j = 0; j < params.phim; j++) {
            if (first_entry[j]) {
                result[j] = (params.nb_i[i] * mod_vecs[i][j]) % params.q;
                first_entry[j] = false;
            } else {
                result[j] = (result[j] + params.nb_i[i]*mod_vecs[i][j]) % params.q;
            }
        }
    }
    return result;
}

uv64 sample_error(const FVParams& params) {
    return params.dgg->GenerateVector(params.phim, params.q);
}

std::vector<uv64> sample_error_dcrt(const FVParamsDCRT& params) {
	return params.paramVec[0].dgg->GenerateVectorDCRT(params.phim, params.p_i);
}

uv64 sample_random_vec_q(const FVParams& params) {
    return get_dug_vector(params.phim, params.q);
}

uv64 sample_random_plaintext_data(const FVParams& params) {
    return get_dug_vector(params.phim, params.p);
}

uv64 sample_random_plaintext_data_fv(const ui64 phim, ui64 p) {
    return get_dug_vector(phim, p);
}

uv64 comp_neg_mod_q(const uv64& a, const FVParams& params) {
    uv64 result(params.phim);
    for (ui32 i = 0; i < params.phim; i++) {
        result[i] = (params.q - a[i])%params.q;
    }
    return result;
}


}  // namespace lbcrypto ends

#endif
