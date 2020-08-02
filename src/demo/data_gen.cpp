#include <iostream>
#include <fstream>  
#include <random>

#include "Common/Defines.h"
#include "Common/Timer.h"
#include "Common/Log.h"

#include "Network/Channel.h"
#include "Network/Session.h"
#include "Network/IOService.h"
#include <pke/gazelle.h>
#include <utils/backend.h>

#include "math/bit_twiddle.h"

using namespace std;
using namespace lbcrypto;
using namespace osuCrypto;

int main(int argc, char** argv) {

    size_t numElements = 20;

    srand (time(NULL));

    {
        std::ofstream outfile ("client1_pen_data.csv");

        for (size_t i = 0; i < numElements; i++)
            outfile << rand() % 100 << std::endl;

        outfile.close();
    }

    {
        std::ofstream outfile ("client2_pen_data.csv");

        for (size_t i = 0; i < numElements; i++)
            outfile << rand() % 100 << std::endl;

        outfile.close();
    }

    {
        std::ofstream outfile ("client3_pen_data.csv");

        for (size_t i = 0; i < numElements; i++)
            outfile << rand() % 100 << std::endl;

        outfile.close();
    }
}

