/**
@file multiparty.h -- Common API for multiparty functionality

Author: Leo de Castro
*/

#ifndef LBCRYPTO_MULTIPARTY_H
#define LBCRYPTO_MULTIPARTY_H

#include "Common/Defines.h"
#include "Common/Timer.h"
#include "Common/Log.h"

#include "Network/Channel.h"
#include "Network/Session.h"
#include "Network/IOService.h"
#include <pke/gazelle.h>
#include "fv_dcrt_params.h"
#include <utils/backend.h>

#include "math/bit_twiddle.h"

using namespace osuCrypto;

namespace lbcrypto {

    // Outputs a keypair that is the multiparty public key and the client's
    // share of the secret key
    // WARNING: Blocks until ServerMPKeyGen is called
    template <typename ParamType>
    KeyPair ClientMPKeyGen(const ParamType& params, Channel& chl, const int verbose = 0);

    // Returns the common public key that is the combined client public keys
    // WARNING: Blocks until ClientMPKeyGen is called
    template <typename ParamType>
    PublicKey ServerMPKeyGen(const ParamType& params, std::vector<Channel>& chls, const int verbose = 0);

    // WARNING: Blocks until ServerMPDecrypt is called
    uv64 ClientMPDecrypt(const SecretKey& sk, const Ciphertext& ct, const FVParams& params, Channel& chl, const int verbose = 0);

    // WARNING: Blocks until ClientMPDecrypt is called
    uv64 ServerMPDecrypt(const FVParams& params, std::vector<Channel>& chls, const int verbose = 0);

}  // namespace lbcrypto ends

#endif
