/**
Initial multiparty demo addition for Sloan workshop.
Uses the optimized parameters from previous projects. Supports about 19 bits of plaintext computation.

Author: Leo de Castro
*/


#include <iostream>

#include "pke/multiparty.h"
#include "utils/read.h"

using namespace std;
using namespace lbcrypto;
using namespace osuCrypto;

//
// Common params
//

ui32 window_size = 10;
ui64 p = 10027009;  // opt::p
DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(0.0);
FVParams test_params {
    opt::q, p, opt::logn, opt::phim,
    (opt::q/p),
    RLWE, std::make_shared<DiscreteGaussianGenerator>(dgg),
    window_size
};
ui32 num_windows = 1 + floor(log2(test_params.q))/test_params.window_size;

ui64 z = opt::z;  // RootOfUnity(test_params.phim << 1, test_params.q);
ui64 z_p = opt::z_p;  // RootOfUnity(test_params.phim << 1, test_params.p);

std::string addr = "localhost";   // Address of the server
int port = 1212;

float scaleConstant = 100;

std::vector<std::string> FILE_NAMES = {"client1_pen_data.csv", "client2_pen_data.csv", "client3_pen_data.csv"};

//
// Server code
//

void ahe_server(const ui32 numClients = 1, const bool verbose = false) {

    std::cout << "Server\n\n";

    // Networking boilderplate
    IOService ios(0);
    std::vector<Channel> chls(numClients);
    for (ui32 i=0; i<numClients; i++) {
        string name = "Client ";
        name += std::to_string(i+1);
        Session sess(ios, addr, port, EpMode::Server);
        chls[i] = sess.addChannel(name);
        chls[i].waitForConnection();
        std::cout << "Server connected to client " << i + 1 << std::endl;
    }

    std::cout << "Server connected to " << numClients << " clients\n\n";

    // Step 1:
    //  Send common seed to clients
    //  Receive public keys from clients
    //  Add the pks together to create the multiparty key.

    PublicKey mpPK = ServerMPKeyGen(test_params, chls);

    Ciphertext ct(test_params.phim);
    Ciphertext ct_squared(test_params.phim);
    for (ui32 i=0; i<numClients; i++) {
        // Step 2:
        //  Receive the encrypted clients' data
        Ciphertext clientCt(test_params.phim);
        Ciphertext clientCtSquared(test_params.phim);
        chls[i].recv(clientCt.a);
        chls[i].recv(clientCt.b);
        chls[i].recv(clientCtSquared.a);
        chls[i].recv(clientCtSquared.b);
        if (verbose) {
            std::cout << "Client " << i+1 << " ct[0]: " << vec_to_str(clientCt.a) << std::endl;
            std::cout << "Client " << i+1 << " ct[1]: " << vec_to_str(clientCt.b) << std::endl;
        }
        std::cout << "Server received encrypted data from client " << i+1 << std::endl;

        // Step 3:
        //  Add together clients' data
        if (i == 0) {
            ct = clientCt;
            ct_squared = clientCtSquared;
        } else {
            ct = EvalAdd(clientCt, ct, test_params);
            ct_squared = EvalAdd(ct_squared, clientCtSquared, test_params);
        }
    }

    // Step 4:
    //  Send results to clients
    //  Receive decryption shares
    //  Recombine shares and send to all clients

    for (size_t i = 0; i < numClients; i++) {
        chls[i].send(ct.a);
        chls[i].send(ct.b);
    }

    uv64 sums = ServerMPDecrypt(test_params, chls);

    for (size_t i = 0; i < numClients; i++) {
        chls[i].send(ct_squared.a);
        chls[i].send(ct_squared.b);
    }

    ServerMPDecrypt(test_params, chls);

    // Networking teardown

    for (ui32 i=0; i<numClients; i++) {
        Session sess = chls[i].getSession();
        chls[i].close();
        sess.stop();
    }
    ios.stop();
	return;
}

//
// Client code
//

void ahe_client(const string name = "Client", const bool verbose = false) {

    std::cout << name << std::endl << std::endl;

    // Networking boilerplate
    IOService ios(0);
    Channel chl;

    AttemptConnect:
    try {
        Session sess(ios, addr, port, EpMode::Client);
        chl = sess.addChannel(name);
        chl.waitForConnection();
    } catch (...) {  // FIXME: It is pretty dangerous to just catch all exceptions like this...
        goto AttemptConnect;
    }

    std::cout << name << " connected to server\n\n";

    // Step 1:
    //  Generate public key and send it to the server.
    //  Receive the multiparty encryption key from the server.
    KeyPair kp = ClientMPKeyGen(test_params, chl);
    PublicKey mpPK = kp.pk;

    // Step 2:
    //  Encrypt and send data
    uv64 data(test_params.phim);
    uv64 data_squared(test_params.phim);
    std::vector<float> preciseData = gen_vec_from_file(FILE_NAMES[atoi(&name.at(name.size() - 1)) - 1]);
    for (size_t i = 0; i < preciseData.size(); i++) {
        data[i] = (ui64)(preciseData[i]);
        data_squared[i] = data[i] * data[i];
    }
    std::cout << "Client input data: " << vec_to_str(preciseData, 0) << std::endl;

    uv64 pt = packed_encode(data, test_params.p, test_params.logn);
    Ciphertext ct = Encrypt(mpPK, pt, test_params);
    uv64 pt_sq = packed_encode(data_squared, test_params.p, test_params.logn);
    Ciphertext ct_squared = Encrypt(mpPK, pt_sq, test_params);
    // std::cout << vec_to_str(ct.a);
    // std::cout << "\n\n\n";
    // std::cout << vec_to_str(ct.b) << std::endl;
    chl.send(ct.a);
    chl.send(ct.b);
    chl.send(ct_squared.a);
    chl.send(ct_squared.b);
    std::cout << name << " sent encrypted data to server\n";

    // Step 4:
    //  Receive the encrypted result
    //  Generate decryption share
    //  Send decryption share to server
    //  Receive combined result
    Ciphertext encResult(test_params.phim);
    chl.recv(encResult.a);
    chl.recv(encResult.b);
    std::cout << name << " received encrypted result from server\n";

    uv64 result = ClientMPDecrypt(kp.sk, encResult, test_params, chl);

    Ciphertext encSquares(test_params.phim);
    chl.recv(encSquares.a);
    chl.recv(encSquares.b);

    uv64 sum_squares = ClientMPDecrypt(kp.sk, encSquares, test_params, chl);

    dv skew(preciseData.size());
    for (size_t i = 0; i < skew.size(); i++) skew[i] = ((float)(sum_squares[i]))/((float)(result[i]*result[i]));

    result.resize(preciseData.size());
    std::cout << "Result: " << vec_to_str(result) << std::endl;
    std::cout << "Variation coefficient: " << vec_to_str(skew, 3) << std::endl;


    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    Session sess = chl.getSession();
    chl.close();
    sess.stop();
    ios.stop();
	return;
}

// Launch code

int main(int argc, char** argv) {

	ftt_precompute(z, test_params.q, test_params.logn);
	ftt_precompute(z_p, test_params.p, test_params.logn);
	encoding_precompute(test_params.p, test_params.logn);
	precompute_automorph_index(test_params.phim);

	if(argc >= 2 && argc <= 3)
	{
		int role = atoi(argv[1]); // 0: server, 1: client
        string name = "Client ";
        name += argv[1];
        if (argc == 2) role ? ahe_client(name) : ahe_server();
        else {
            int numClients = atoi(argv[2]);
            if (argc == 3) role ? ahe_client(name) : ahe_server(numClients);
            else throw std::runtime_error("Could not parse arguments!");
        }
	}
    else
    {
        std::cout << "this program takes runtime arguments.\n\n"
            << "to run the multiparty addition, run\n\n"
            << "    fv-multiparty-online [(0-9)*? (0-9)*?]\n\n"
            << "the first argument {0,1} specifies in which case the program will\n"
            << "run between two terminals, where each one was set to the opposite value. e.g.\n\n"
            << "    fv-multiparty-online 0  <--  Server\n\n"
            << "    fv-multiparty-online 1  <--  Client\n\n"
            << "If the code is running in server mode, the second argument is to determine the number of clients. The default is 1.\n"
            << "If the code is running in client mode, the second argument determines whether the data used is entered by the user. The default value is false.\n"
            << "These programs are fully networked and try to connect at " << addr << ":" << port << ".\n"
            << std::endl;
    }
}
