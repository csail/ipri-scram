#include <iostream>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <assert.h>

#include "backend.h"

#ifndef LBCRYPTO_TEST_H
#define LBCRYPTO_TEST_H

namespace lbcrypto {

sv64 to_signed(uv64 v, ui64 p);
std::string vec_to_str_cmplx(const cv& v);
void check_vec_eq_cmplx(const cv& v1, const cv& v2, const std::string& what);

template<typename IntType>
std::string vec_to_str(std::vector<IntType> v, int precision = 10){
	std::ostringstream out;
	out.precision(precision);
	for (size_t i = 0; i < v.size(); i++) out << std::fixed << v[i] << " ";
	return out.str();
}

template<typename IntType>
std::string mat_to_str(std::vector<std::vector<IntType>> m){
	std::string str;
	for(ui32 j=0; j<m.size(); j++){
		for(ui32 i=0; i<m[0].size(); i++){
			str += std::to_string(m[j][i]) + " ";
		}
		str += "\n";
	}

	return str;
}

template<typename IntType>
void check_vec_eq(std::vector<IntType> v1, std::vector<IntType> v2, const std::string& what){
	if(v1.size() != v2.size()) {
		std::cout << vec_to_str(v1) << std::endl;
		std::cout << vec_to_str(v2) << std::endl;
		std::cout << "Size mismatch!\n";
		throw std::logic_error(what);
	}

	for (size_t i = 0; i < v1.size(); i++) {
		if (v1[i] != v2[i]) {
			std::cout << vec_to_str(v1) << std::endl;
			std::cout << vec_to_str(v2) << std::endl;
			throw std::logic_error(what);
		}
	}

	return;
}

template<typename IntType>
void check_vec_eq_approx(const std::vector<IntType>& v1, const std::vector<IntType>& v2, const std::string& what) {
	if(v1.size() != v2.size()) {
		std::cout << vec_to_str(v1) << std::endl;
		std::cout << vec_to_str(v2) << std::endl;
		std::cout << "Size mismatch!\n";
		throw std::logic_error(what);
	}

	for (size_t i = 0; i < v1.size(); i++) {
		if (std::abs(v1[i] - v2[i]) > 0.1*std::max(v1[i], v2[i])) {
			std::cout << vec_to_str(v1) << std::endl;
			std::cout << vec_to_str(v2) << std::endl;
			std::cout << "Mismatch at index " << i << std::endl;
			std::cout << v1[i] << " != " << v2[i] << std::endl;
			throw std::logic_error(what);
		}
	}

	return;
}

template<typename IntType>
void check_mat_eq(
		std::vector<std::vector<IntType>> m1,
		std::vector<std::vector<IntType>> m2,
		const std::string& what){
	if(m1.size() != m2.size()){
		std::cout << "Sizes: " << m1.size() << " " << m1.size() << std::endl;
		throw std::logic_error(what);
		// return m2.size();
	} else {
		for(ui32 n=0; n<m1.size(); n++){
			if(m1[n] != m2[n]){
				std::cout << "Mismatch on row: " << n << std::endl;
				std::cout << vec_to_str(m1[n]) << std::endl;
				std::cout << vec_to_str(m2[n]) << std::endl;
				//return n;
				throw std::logic_error(what);
			}
		}
	}

	// return m1.size();
}

}
#endif
