/*
 * test.cpp
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#include <utils/backend.h>
#include "utils/test.h"

namespace lbcrypto {

sv64 to_signed(uv64 v, ui64 p){
	sv64 sv(v.size());
	ui64 bound = p >> 1;
	for(ui32 i=0; i<v.size(); i++){
		sv[i] = (v[i] > bound) ? -1*(si64)(p-v[i]): v[i];
	}

	return sv;
}

std::string vec_to_str_cmplx(const cv& v) {
	std::string str;
	for (ui32 i=0; i<v.size(); i++)
		str += "(" + std::to_string(v[i].real()) + ", " + std::to_string(v[i].imag()) + ") ";
	return str;
}

void check_vec_eq_cmplx(const cv& v1, const cv& v2, const std::string& what) {
	if(v1.size() != v2.size()) {
		std::cout << vec_to_str_cmplx(v1) << std::endl;
		std::cout << vec_to_str_cmplx(v2) << std::endl;
		std::cout << "Size mismatch!\n";
		throw std::logic_error(what);
	}

	for (size_t i = 0; i < v1.size(); i++) {
		if (std::abs(v1[i] - v2[i]) > 0.0001) {
			if (!(v1[i] == -0.0 && v2[i] == 0.0) && !(v1[i] == 0.0 && v2[i] == -0.0)) {
				std::cout << vec_to_str_cmplx(v1) << std::endl;
				std::cout << vec_to_str_cmplx(v2) << std::endl;
				std::cout << "Mismatch at index " << i << std::endl;
				std::cout << v1[i] << " != " << v2[i] << std::endl;
				throw std::logic_error(what);
			}
		}
	}

	return;
}

}
