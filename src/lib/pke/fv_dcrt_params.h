

#ifndef LB_CRYPTO_FV_DCRT_PARAMS_H
#define LB_CRYPTO_FV_DCRT_PARAMS_H

#include "fv_dcrt.h"

namespace lbcrypto {

	FVParamsDCRT gen_fv_three_limb_fast_dcrt_params(); 
    void precompute_dcrt_params(const FVParamsDCRT& dcrt_params); 
    
}  // namespace lbcrypto ends

#endif
