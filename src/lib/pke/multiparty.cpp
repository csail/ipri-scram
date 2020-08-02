/**
@file multiparty.cpp -- Common API for multiparty functionality

Author: Leo de Castro
*/

#include "multiparty.h"

using namespace osuCrypto;

namespace lbcrypto {

    // Outputs a keypair that is the multiparty public key and the client's
    // share of the secret key
    template KeyPair ClientMPKeyGen(const FVParams& params, Channel& chl, const int verbose);
    template <typename ParamType>
    KeyPair ClientMPKeyGen(const ParamType& params, Channel& chl, const int verbose) {
        block seed; chl.recv(seed);
        PRNG prng(seed);
        KeyPair kp = KeyGen(prng, params);
        if (verbose) std::cout << "Client generated keypair\n";
        chl.send(kp.pk.a);
        chl.send(kp.pk.b);
        if (verbose > 10) {
            std::cout << "Client pk[0]: " << vec_to_str(kp.pk.a) << std::endl;
            std::cout << "Client pk[1]: " << vec_to_str(kp.pk.b) << std::endl;
        }
        if (verbose) std::cout << "Client sent public key to server\n";

        PublicKey mpPK(params.phim);
        chl.recv(mpPK.a);
        chl.recv(mpPK.b);
        if (verbose) std::cout << "Client received public key from server\n";

        return KeyPair(mpPK, kp.sk);
    }

    // Returns the common public key that is the combined client public keys
    template PublicKey ServerMPKeyGen(const FVParams& params, std::vector<Channel>& chls, const int verbose);
    template <typename ParamType>
    PublicKey ServerMPKeyGen(const ParamType& params, std::vector<Channel>& chls, const int verbose) {
        ui32 numClients = chls.size();

        block commonSeed = sysRandomSeed();
        for (size_t i = 0; i < numClients; i++) chls[i].send(commonSeed);

        PublicKey mpPK;
        for (size_t i = 0; i < numClients; i++) {
            PublicKey clientPK(params.phim);
            chls[i].recv(clientPK.a);
            chls[i].recv(clientPK.b);

            if (i == 0) mpPK = clientPK;
            else mpPK = MPPKAdd(clientPK, mpPK, params);
        }
        if (verbose) std::cout << "Server received client public keys\n";

        if (verbose > 10) {
            std::cout << "Combined pk[0]: " << vec_to_str(mpPK.a) << std::endl;
            std::cout << "Combined pk[1]: " << vec_to_str(mpPK.b) << std::endl;
        }
        for (ui32 i=0; i<numClients; i++) {
            chls[i].send(mpPK.a);
            chls[i].send(mpPK.b);
            if (verbose) std::cout << "Server sent pk to client " << i + 1 << std::endl;
        }

        return mpPK;
    }

    uv64 ClientMPDecrypt(const SecretKey& sk, const Ciphertext& ct, const FVParams& params, Channel& chl, const int verbose) {
        ui32 numClients;
        chl.recv(numClients);

        uv64 decShare = DecryptShare(sk, ct, numClients, params);
        chl.send(decShare);
        if (verbose) std::cout << "Client sent decryption share to server\n";

        uv64 result(params.phim);
        chl.recv(result);

        return result;
    }

    uv64 ServerMPDecrypt(const FVParams& params, std::vector<Channel>& chls, const int verbose) {
        ui32 numClients = chls.size();

        for (size_t i = 0; i < numClients; i++) chls[i].send(numClients);

        uv64 toDecode(params.phim, 0);
        for (size_t i = 0; i < numClients; i++) {
            uv64 clientShare;
            chls[i].recv(clientShare);
            toDecode = comp_add_mod_q(toDecode, clientShare, params);
        }

        toDecode = MPDecryptFin(toDecode, params);
        uv64 result = packed_decode(toDecode, params.p, params.logn);
        for (size_t i = 0; i < params.phim; i++) result[i] /= numClients;

        for (ui32 i=0; i<numClients; i++) chls[i].send(result);

        if (verbose > 10) std::cout << vec_to_str(result) << std::endl;
        if (verbose) std::cout << "Server sent decryption shares to clients.\n";

        return result;
    }

}  // namespace lbcrypto ends
