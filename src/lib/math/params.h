#ifndef LBCRYPTO_MATH_PARAMS_H
#define LBCRYPTO_MATH_PARAMS_H

#include "../utils/backend.h"
#include "math/bit_twiddle.h"

namespace lbcrypto {
	namespace opt {
		extern ui32 logn;
		extern ui32 phim;

		extern ui64 q;
		extern ui64 z;
		extern ui64 v0_q;
		extern ui64 s0;
		extern ui64 q2;
		extern ui64 q4;

		extern ui64 p;
		extern ui64 p2;
		extern ui64 z_p;
		extern ui64 mu;
		extern ui64 mu_h;
		extern ui64 mu_l;

		inline ui64 modp_part(ui64 a){
			// The constant here is 2*ceil(log2(p))+2
			return (a - ((a*mu) >> 42)*p);
		}

		/*inline ui64 modp_part(ui64 a){
			return  (a - ((a*mu_h + ((a*mu_l) >> 4)) >> 40)*p);
		}*/

		inline ui64 modp_full(ui64 a){
			ui64 b = modp_part(a);
			return ((b >= p)? b-p: b);
		}

		inline ui64 modp_finalize(ui64 a){
			return ((a >= p)? a-p: a);
		}

		inline ui64 modq_part(ui128 x){
    		ui128 qq = ((ui128)v0_q*(x >> 64) + (x << s0));
    		ui128 r = (x - (qq >> 64)*(ui128)q);
			return (ui64)r;
		}

		inline ui64 modq_full(ui128 a){
			ui64 r = modq_part(a);
			return ((r >= q)? r-q: r);
		}

		inline ui64 modq_part(ui64 x){
			return x - (x >> (64-s0))*q;
		}

		inline ui64 modq_full(ui64 a){
			ui64 r = modq_part(a);
			return ((r >= q)? r-q: r);
		}

		inline ui64 sub_modq_part(ui64 a, ui64 b){
			return modq_part(a + q2 - b);
		}

		inline ui64 mul_modq_part(ui64 a, ui64 b){
    		ui128 c = (ui128)a*(ui128)b ;
			return modq_part(c);
		}

		inline ui64 lshift_modq_part(ui64 a, ui32 shift){
			ui128 c = ((ui128)a << shift); // 124b number
			return modq_part(c);
		}
	}
}


#endif
