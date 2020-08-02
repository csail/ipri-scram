/*
 * fv.cpp
 *
 *	This implementation is broadly similar to the PALISADE FV implementation
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#include <iostream>
#include <map>
#include <memory>
using std::shared_ptr;

#ifndef LBCRYPTO_CRYPTO_FV_C
#define LBCRYPTO_CRYPTO_FV_C

#include "math/params.h"
#include "math/transfrm.h"
#include "math/automorph.h"
#include "pke/encoding.h"
#include "pke/fv.h"
#include "utils/test.h"

#include <iostream>

namespace lbcrypto {

std::map<ui32, shared_ptr<RelinKey>> g_rk_map;

uv64 NullEncrypt(uv64& pt, const FVParams& params){
	return ToEval(pt, params);
}

uv64 NullEncryptDelta(uv64& pt, const FVParams& params){
	uv64 pt_delta = uv64(params.phim);
	for(ui32 n=0; n<params.phim; n++){
        pt_delta[n] = mod_mul(pt[n], params.delta, params.q);
	}
	return ToEval(pt_delta, params);
}

Ciphertext Encrypt(const PublicKey& pk, uv64& pt, const FVParams& params){
	uv64 u(params.phim);
	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	// u is a small error polynomial
	if (params.mode == RLWE) {
		u = params.dgg->GenerateVector(params.phim, params.q);
	} else {
		u = get_tug_vector(params.phim, params.q);
	}

	// ea and eb are also small error polynomials
	uv64 ea = params.dgg->GenerateVector(params.phim, params.q);
	uv64 eb = params.dgg->GenerateVector(params.phim, params.q);

	return EncryptLimb(pk, pt, u, ea, eb, params);
}


Ciphertext EncryptLimb(const PublicKey& pk, uv64& pt, const uv64& uc,
		const uv64& eac, const uv64& ebc, const FVParams& params){
	auto u = ToEval(uc, params);

	Ciphertext ct(params.phim);
	ct.a = ToEval(eac, params);

	// ct.b has the message times delta plus error eb
	for(ui32 i=0; i<params.phim; i++){
        ct.b[i] = mod_mul(pt[i], params.delta, params.q) + ebc[i];
	}
	ct.b = ToEval(ct.b, params);

	for(ui32 i=0; i<params.phim; i++){
        ct.a[i] = mod(mod_mul(pk.a[i], u[i], params.q) + ct.a[i], params.q);
        ct.b[i] = mod(mod_mul(pk.b[i], u[i], params.q) + ct.b[i], params.q);
	}

	// Final form: (all mod q)
	//    ct = (pk.a * u + ea, pk.b * u + m*delta + eb)
	//		 = (a * u + ea, -(a.s + e) * u + m*delta + eb)
	//       = (a*u + ea, -a*s*u - e*u + m*delta + eb)
	return ct;
}

Ciphertext Encrypt(const SecretKey& sk, uv64& pt, const FVParams& params){
	auto e = params.dgg->GenerateVector(params.phim, params.q);
	return EncryptLimb(sk, pt, e, params);
}

Ciphertext EncryptLimb(const SecretKey& sk, uv64& pt, const uv64& e, const FVParams& params){
	Ciphertext ct(params.phim);
    ct.a = get_dug_vector(params.phim, params.q);

	for(ui32 i=0; i<params.phim; i++){
        ct.b[i] = mod_mul(pt[i], params.delta, params.q) + e[i];
	}
	ct.b = ToEval(ct.b, params);


	for(ui32 i=0; i<params.phim; i++){
        auto prod = mod_mul(ct.a[i], sk.s[i], params.q);
        ct.b[i] = mod(ct.b[i] + params.q - prod, params.q);
	}

	return ct;
}

uv64 Decrypt(const SecretKey& sk, const Ciphertext& ct, const FVParams& params){
	// Ciphertext comes in as
	//   (a*u + ea, -a*s*u - e*u + m*delta + eb)

	uv64 pt(params.phim);
	for(ui32 i=0; i<params.phim; i++){
        pt[i] = mod_mul(ct.a[i], sk.s[i], params.q) + ct.b[i];
	}
	// pt has the form
	//   a*u*s + ea*s -a*s*u - e*u + m*delta + eb
	//  = ea*s - e*u + m*delta + eb
	//  = m * delta + small
	pt = ToCoeff(pt, params);

	auto delta_by_2 = params.delta/2;
	for(ui32 i=0; i<params.phim; i++){
		pt[i] = (pt[i] + delta_by_2)/params.delta;
	}

	return pt;
}

uv64 DecryptShare(const SecretKey& sk, const Ciphertext& ct, const ui32 numClients, const FVParams& params) {
	uv64 pt(params.phim);

	uv64 stripKey = comp_scal_mult_mod_q(ToCoeff(comp_mult_mod_q(ct.a, sk.s, params), params), numClients, params);
	pt = comp_add_mod_q(ToEval(stripKey, params), ct.b, params);
	// for(ui32 i=0; i<params.phim; i++)
		// pt[i] = mod_mul(ct.a[i], sk.s[i], params.q) + ct.b[i];

	// return pt;

	// uv64 errorFlood(params.phim, 0)
	uv64 errorFlood = comp_mult_mod_q(ToEval(get_dug_vector(params.phim, params.p), params), ToEval(params.dgg->GenerateVector(params.phim, params.q), params), params);
	return comp_add_mod_q(pt, errorFlood, params);
}

uv64 MPDecryptFin(const uv64& toScaleDown, const FVParams& params) {
	uv64 pt = ToCoeff(toScaleDown, params);
	auto delta_by_2 = params.delta/2;

	for(ui32 i=0; i<params.phim; i++)
		pt[i] = (pt[i] + delta_by_2)/params.delta;

	return pt;
}

sv64 Noise(const SecretKey& sk, const Ciphertext& ct, const FVParams& params){
	uv64 e(params.phim);
	for(ui32 i=0; i<params.phim; i++){
		e[i] = mod_mul(ct.a[i], sk.s[i], params.q) + ct.b[i];
	}
	e = ToCoeff(e, params);

	sv64 es(params.phim);
	auto delta_by_2 = params.delta/2;
	for(ui32 i=0; i<params.phim; i++){
		e[i] = (e[i] % params.delta);
		es[i] = (e[i] > delta_by_2) ? (e[i] - params.delta) : e[i];
	}

	return es;
};

double NoiseMargin(const SecretKey& sk, const Ciphertext& ct, const FVParams& params){
	sv64 noise = Noise(sk, ct, params);

	ui64 noise_max = 0;
	for(uint32_t i=0; i<params.phim; i++){
		ui64 noise_abs = std::abs(noise[i]);
		noise_max = std::max(noise_max, noise_abs);
	}

	return (std::log2(params.delta)-std::log2(noise_max));
}

KeyPair KeyGen(const FVParams& params){
	// Both options for secret key distributions generate short keys
	uv64 s(params.phim);
	if (params.mode == RLWE) {
		s = params.dgg->GenerateVector(params.phim, params.q);
	} else {
		s = get_tug_vector(params.phim, params.q);
	}

	auto e = params.dgg->GenerateVector(params.phim, params.q);

	return KeyGenLimb(s, e, params);
}

KeyPair KeyGen(osuCrypto::PRNG& prng, const FVParams& params) {
	SecretKey sk(params.phim);
	// uv64 s(params.phim);
	if (params.mode == RLWE) {
		sk.s = ToEval(params.dgg->GenerateVector(params.phim, params.q), params);
	} else {
		sk.s = ToEval(get_tug_vector(params.phim, params.q), params);
	}

	PublicKey pk(params.phim);
	// Public key is a pair of the form (a, e - a.s)

	for (size_t i = 0; i < params.phim; i++)
		pk.a[i] = prng.get<ui64>() % params.q;

	// Starts out pk.b with just the error
	pk.b = ToEval(params.dgg->GenerateVector(params.phim, params.q), params);

	for(ui32 i=0; i<params.phim; i++){
		// Each prod = a[i] * s[i]
		// Subract prod from error to get final pk.b
        auto prod = mod_mul(pk.a[i], sk.s[i], params.q);
        pk.b[i] = mod(pk.b[i] + params.q - prod, params.q);
	}

	// Final form:
	//   ((a, e - a.s), s)
	return	KeyPair(pk, sk);
}

MPKeyPair MPKeyGen(const FVParams& params) {
	ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

	uv64 s(params.phim);
	if (params.mode == RLWE) {
		s = params.dgg->GenerateVector(params.phim, params.q);
	} else {
		s = get_tug_vector(params.phim, params.q);
	}

	s = ToEval(s, params);

	uv64 pka(params.phim, 1);  //  = get_dug_vector(params.phim, params.q);
	std::vector<uv64> pkaPowers = powers_of_base(pka, params.window_size, num_windows, params.q);

	for (size_t i = 0; i < num_windows; i++) {
		auto e = ToEval(params.dgg->GenerateVector(params.phim, params.q), params);
		pkaPowers[i] = comp_sub_mod_q(e, comp_mult_mod_q(pkaPowers[i], s, params), params);
	}

	MPPublicKey pk(pka, pkaPowers);
	SecretKey sk(params.phim); sk.s = s;
	return MPKeyPair(pk, sk);
}

KeyPair KeyGenLimb(const uv64& s, const uv64& e, const FVParams& params){
	SecretKey sk(params.phim);
	sk.s = ToEval(s, params);

	PublicKey pk(params.phim);
	// Public key is a pair of the form (a, e - a.s), which is equivalent
	// to (a, -(a.s + e')), since the the error distributions are symmetric around the origin

	// Draws a uniformly random vector for a
    pk.a = get_dug_vector(params.phim, params.q);

	// Starts out pk.b with just the error
	pk.b = ToEval(e, params);

	for(ui32 i=0; i<params.phim; i++){
		// Each prod = a[i] * s[i]
		// Subract prod from error to get final pk.b
        auto prod = mod_mul(pk.a[i], sk.s[i], params.q);
        pk.b[i] = mod(pk.b[i] + params.q - prod, params.q);
	}

	// Final form:
	//   ((a, e - a.s), s)
	return	KeyPair(pk, sk);
}

KeyPair KeyGenLimb(osuCrypto::PRNG& prng, const uv64& s, const uv64& e, const FVParams& params){
	std::cerr << "KeyGenlimb started\n";
	SecretKey sk(params.phim);
	sk.s = ToEval(s, params);
	std::cerr << "SecretKey created\n";
	PublicKey pk(params.phim);
	// Public key is a pair of the form (a, e - a.s), which is equivalent
	// to (a, -(a.s + e')), since the the error distributions are symmetric around the origin

	// Draws a uniformly random vector for a

	for (size_t i = 0; i < params.phim; i++)
		pk.a[i] = prng.get<ui64>() % params.q;
	std::cerr << "PK.a created\n";

	// Starts out pk.b with just the error
	pk.b = ToEval(e, params);
	std::cerr << "Error to eval\n";
	for(ui32 i=0; i<params.phim; i++){
		// Each prod = a[i] * s[i]
		// Subract prod from error to get final pk.b
        auto prod = mod_mul(pk.a[i], sk.s[i], params.q);
        pk.b[i] = mod(pk.b[i] + params.q - prod, params.q);
	}
	std::cerr << "Pk.b created\n";
	// Final form:
	//   ((a, e - a.s), s)
	return	KeyPair(pk, sk);
}

PublicKey MPPKGen(const std::vector<MPPublicKey>& pks, const FVParams& params) {
	ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

	ui32 numClients = pks.size();
	PublicKey result(params.phim);
	for (size_t cl = 0; cl < numClients; cl++) {
		PublicKey currClPK(params.phim);
		// compute product of other clients' a's
		uv64 otherClientsAs(params.phim, 1);
		for (size_t othCl = 0; othCl < numClients; othCl++) {
			if (othCl != cl) {
				otherClientsAs = comp_mult_mod_q(otherClientsAs, pks[othCl].a, params);
			}
		}

		currClPK.a = comp_mult_mod_q(otherClientsAs, pks[cl].a, params);
		currClPK.b = uv64(params.phim, 0);
		std::vector<uv64> decompOtherAs = base_decompose(otherClientsAs, params.window_size, num_windows);
		for (size_t w = 0; w < num_windows; w++)
			currClPK.b = comp_add_mod_q(currClPK.b, comp_mult_mod_q(decompOtherAs[w], pks[cl].b[w], params), params);

		if (cl == 0) result = currClPK;
		else result = MPPKAdd(currClPK, result, params);
	}

	return result;
}

PublicKey MPPKAdd(const PublicKey& pk1, const PublicKey& pk2, const FVParams& params) {
	assert(pk1.a == pk2.a);
	PublicKey result(params.phim);
	result.a = pk1.a;
	result.b = comp_add_mod_q(pk1.b, pk2.b, params);
	return result;
}

template Ciphertext EvalAdd(const Ciphertext& ct1, const Ciphertext& ct2, const FVParams& params);
template PublicKey EvalAdd(const PublicKey& ct1, const PublicKey& ct2, const FVParams& params);

template <typename CryptoObject>
CryptoObject EvalAdd(const CryptoObject& ct1, const CryptoObject& ct2, const FVParams& params) {
	CryptoObject sum(params.phim);

	for(ui32 i=0; i<params.phim; i++){
		sum.a[i] = mod(ct1.a[i] + ct2.a[i], params.q);
		sum.b[i] = mod(ct1.b[i] + ct2.b[i], params.q);
	}

	return sum;
}

// No increase in error!
// Just add the message to the second part of the ciphertext
// NOTE: Assumes plaintext is NullEncryptDelta. i.e. it's already been scaled
Ciphertext EvalAddPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params){
	// Ciphertext comes in as
	// (a*u + ea, -a*s*u - e*u + m1*delta + eb)
	Ciphertext sum(params.phim);
	sum.a = ct.a;

	for(ui32 i=0; i<params.phim; i++){
        sum.b[i] = mod(ct.b[i] + pt[i], params.q);
	}

	// Ciphertext leaves as
	//  (a*u + ea, -a*s*u - e*u + m1*delta + m2 + eb)
	return sum;
}

Ciphertext EvalSub(const Ciphertext& ct1, const Ciphertext& ct2, const FVParams& params){
	Ciphertext diff(params.phim);

	for(ui32 i=0; i<params.phim; i++){
        diff.a[i] = mod(ct1.a[i] + params.q - ct2.a[i], params.q);
        diff.b[i] = mod(ct1.b[i] + params.q - ct2.b[i], params.q);
	}

	return diff;
}

Ciphertext EvalSubPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params){
	Ciphertext diff(params.phim);
	diff.a = ct.a;

	for(ui32 i=0; i<params.phim; i++){
        diff.b[i] = mod(ct.b[i] + params.q - pt[i], params.q);
	}

	return diff;
}

Ciphertext EvalNegate(const Ciphertext& ct, const FVParams& params){
	Ciphertext neg(params.phim);

	for(ui32 i=0; i<params.phim; i++){
        neg.a[i] = mod(params.q - ct.a[i], params.q);
        neg.b[i] = mod(params.q - ct.b[i], params.q);
	}

	return neg;
}


Ciphertext EvalMultPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params){
	// Ciphertext comes in as
	// (a*u + ea, -a*s*u - e*u + m1*delta + eb)

	Ciphertext prod(params.phim);

	for(ui32 i=0; i<params.phim; i++){
        prod.a[i] = mod_mul(ct.a[i], pt[i], params.q);
        prod.b[i] = mod_mul(ct.b[i], pt[i], params.q);
	}

	// Ciphertext leaves as
	// ((a*u + ea)*m2, (-a*s*u - e*u + m1*delta + eb)*m2)
	return prod;
}

RelinKey KeySwitchGen(const SecretKey& orig_sk, const SecretKey& new_sk, const FVParams& params){
	// This works because q is never a power of 2, so the floor is 1 less than size of q
	ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

	// Consider changing shape of rk for better locality
	RelinKey rk(params.phim, num_windows);

	for (ui32 i=0; i<num_windows; i++) {
        rk.a[i] = get_dug_vector(params.phim, params.q);
		rk.b[i] = ToEval(params.dgg->GenerateVector(params.phim, params.q), params);

		for(ui32 j=0; j<params.phim; j++){
            rk.b[i][j] += mod_mul((ui64)1 << (i*params.window_size), orig_sk.s[j], params.q);
            auto prod = mod_mul(rk.a[i][j], new_sk.s[j], params.q);
            rk.b[i][j] = mod(rk.b[i][j] + params.q - prod, params.q);
		}
	}

	return rk;
}

std::vector<uv64> HoistedDecompose(const Ciphertext& ct, const FVParams& params){
	// This works because q is never a power of 2, so the floor is 1 less than size of q
	ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

	auto ct_a_coeff = ToCoeff(ct.a, params);

	auto digits_ct = base_decompose(ct_a_coeff, params.window_size, num_windows);
	for(ui32 i=0; i<num_windows; i++){
		digits_ct[i] = ToEval(digits_ct[i], params);
	}

	return digits_ct;
}

Ciphertext KeySwitchDigits(const RelinKey& rk, const Ciphertext& ct,
		const std::vector<uv64> digits_ct, const FVParams& params){
	// This works because q is never a power of 2, so the floor is 1 less than size of q
	ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

	uv128 ct_a(params.phim);
	uv128 ct_b(ct.b.begin(), ct.b.end());

	for (ui32 i=0; i<num_windows; i++) {
		for (ui32 j=0; j<params.phim; j++){
			ct_a[j] += ((ui128)(digits_ct[i][j]) * (ui128)(rk.a[i][j]));
			ct_b[j] += ((ui128)(digits_ct[i][j]) * (ui128)(rk.b[i][j]));
		}
	}

	Ciphertext ct_new(params.phim);
	for (ui32 j=0; j<params.phim; j++){
        ct_new.a[j] = mod(ct_a[j], params.q);
        ct_new.b[j] = mod(ct_b[j], params.q);
	}

	return ct_new;
}

Ciphertext KeySwitch(const RelinKey& rk, const Ciphertext& ct, const FVParams& params){
	auto digits_ct = HoistedDecompose(ct, params);
	return KeySwitchDigits(rk, ct, digits_ct, params);
}

Ciphertext EvalAutomorphismDigits(const ui32 rot, const RelinKey& rk, const Ciphertext& ct,
		const std::vector<uv64>& digits_ct, const FVParams& params){
	// This works because q is never a power of 2, so the floor is 1 less than size of q
	ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

	auto ct_b_rot = automorph(ct.b, rot);

	uv128 ct_a(params.phim);
	uv128 ct_b(ct_b_rot.begin(), ct_b_rot.end());

	for (ui32 i=0; i<num_windows; i++) {
		auto digit_rot = automorph(digits_ct[i], rot);
		for (ui32 j=0; j<params.phim; j++){
			ct_a[j] += ((ui128)(digit_rot[j]) * (ui128)(rk.a[i][j]));
			ct_b[j] += ((ui128)(digit_rot[j]) * (ui128)(rk.b[i][j]));
		}
	}

	Ciphertext ct_rot(params.phim);
	for (ui32 j=0; j<params.phim; j++){
        ct_rot.a[j] = mod(ct_a[j], params.q);
        ct_rot.b[j] = mod(ct_b[j], params.q);
	}

	return ct_rot;
}

Ciphertext EvalAutomorphism(const ui32 rot, const Ciphertext& ct, const FVParams& params){
	const auto digits_ct = HoistedDecompose(ct, params);
	const auto rk = g_rk_map[rot];
	return EvalAutomorphismDigits(rot, (*rk), ct, digits_ct, params);
}

void EvalAutomorphismKeyGen(const SecretKey& sk,
	const uv32& index_list, const FVParams& params){
	for (ui32 i = 0; i < index_list.size(); i++){
		SecretKey sk_rot(params.phim);
		sk_rot.s = automorph(sk.s, index_list[i]);
		g_rk_map[index_list[i]] = std::make_shared<RelinKey>(KeySwitchGen(sk_rot, sk, params));
	}

	return;
}

shared_ptr<RelinKey> GetAutomorphismKey(ui32 rot){
	return g_rk_map[rot];
}

Ciphertext AddRandomNoise(const Ciphertext& ct, const FVParams& params){
	uv64 random_eval = get_dug_vector(params.phim, params.p);
	random_eval[0] = 0; //first plainext slot does not need to change

	uv64 random_coeff = packed_encode(random_eval, params.p, params.logn);

	Ciphertext random_ct(params.phim);
	random_ct.b = NullEncrypt(random_coeff, params);

	return EvalAdd(ct, random_ct, params);
};


uv64 comp_mult_mod_q(const uv64& a, const uv64& b, const FVParams& params) {
    uv64 result(params.phim);
    for (ui32 i = 0; i < params.phim; i++) {
        result[i] = mod_mul(a[i], b[i], params.q);
    }
    return result;
}

uv64 comp_add_mod_q(const uv64& a, const uv64& b, const FVParams& params) {
    uv64 result(params.phim);
    for (ui32 i = 0; i < params.phim; i++) {
        result[i] = (a[i] + b[i])%params.q;
    }
    return result;
}

uv64 comp_sub_mod_q(const uv64& a, const uv64& b, const FVParams& params) {
    uv64 result(params.phim);
    for (ui32 i = 0; i < params.phim; i++) {
        result[i] = ((params.q + a[i]) - b[i])%params.q;
    }
    return result;
}

uv64 comp_scal_mult_mod_q(const uv64& a, const ui64 d, const FVParams& params) {
    uv64 result(params.phim);
    for (ui32 i = 0; i < params.phim; i++) {
        result[i] = mod_mul(a[i], d, params.q);
    }
    return result;
}

}  // namespace lbcrypto ends

#endif
