#include "pke/fv_dcrt_params.h"

namespace lbcrypto {

    FVParamsDCRT gen_fv_three_limb_fast_dcrt_params() {
		// Plaintext modulus. ~41 bits. 1 mod 2048
		ui64 p = 2199023190017;

		// Ciphertext moduli. All ~60 bits. All 1 mod 8192
		ui64 q_1 = 576342537627353089;
		ui64 q_2 = 1152685075254706177;
		ui64 q_3 = 2305370150509412353;
		bui q = BigUnsigned(q_1)*BigUnsigned(q_2)*BigUnsigned(q_3);

		bui big_delt = q/p;

		uv64 mod_vec = {q_1, q_2, q_3};
		ui32 num_moduli = 3;
		double dgg_std_dev = 4;
		ui32 window_size = 9;  // Still don't know what this does....

		// ui32 phim = 8192; ui32 logn = 13;   // m = 16384
        ui32 phim = 2048; ui32 logn = 11;
		// ui32 phim = 4; ui32 logn = 2;   // m = 8

		std::vector<FVParams> param_vec(num_moduli);
		for (ui32 i = 0; i < num_moduli; i++) {
			param_vec[i] = FVParams{
				mod_vec[i], p,
				logn, phim,
				mod(big_delt, mod_vec[i]),
				OPTIMIZED,
				std::make_shared<DiscreteGaussianGenerator>(DiscreteGaussianGenerator(dgg_std_dev)),
				window_size
			};
		}

		bigV n_i(num_moduli);
		for (ui32 i = 0; i < num_moduli; i++) {
			n_i[i] = 1;
		}
		for (ui32 i = 0; i < num_moduli; i++) {
			for (ui32 j = 0; j < num_moduli; j++) {
				if (i != j) {
					n_i[i] = (n_i[i] * mod_vec[j])%q;
				}
			}
		}
		bigV nb_i(num_moduli);
		for (ui32 i = 0; i < num_moduli; i++) {
			bui b_i = modinv(n_i[i], mod_vec[i]);
			nb_i[i] = (n_i[i]*b_i) % q;
		}
		uv64 round_coeffs = {1536913433672941570, 2305370150509412349, 768456716836470787};

		return FVParamsDCRT{ q, p, logn, phim, big_delt, dgg_std_dev, num_moduli, mod_vec, nb_i, round_coeffs, q_3/p, param_vec };
	}

	void precompute_dcrt_params(const FVParamsDCRT& dcrt_params) {
		// ui64 z_p = 1783406912479;
        ui64 z_p = 1023355466891;
        // ui64 z_p = RootOfUnity(dcrt_params.phim << 1, dcrt_params.p);
        // std::cerr << "z_p: " << z_p << std::endl;
		ftt_precompute(z_p, dcrt_params.p, dcrt_params.logn);
		encoding_precompute(dcrt_params.p, dcrt_params.logn);
		precompute_automorph_index(dcrt_params.phim);

        // uv64 zs = {316543615728606321, 87705172243007265, 429947351330200776};
        uv64 zs = {434152673613154973, 837814914427536155, 988775721871004542};
		for (ui32 i = 0; i < dcrt_params.num_moduli; i++) {
			FVParams fv_params = dcrt_params.paramVec[i];
			ui64 z = zs[i];
            // ui64 z = RootOfUnity(fv_params.phim << 1, fv_params.q);
            // std::cerr << "z: " << z << std::endl;
			ftt_precompute(z, fv_params.q, fv_params.logn);
		}
	}

}  // namespace lbcrypto ends
