#include "read.h"

using namespace std;

std::vector< std::vector<float> > get_vecs_from_file(string file){
	vector< vector<float> > data;
    ifstream myfile(file);

    if ( myfile.is_open() ){
    	vector<float> BOFA;
    	vector<float> JP;
    	vector<float> Wells;

    	float bofa, jp, wells;
    	char delimiter;
        // Read the file.
        myfile.ignore(1000, '\n');
        while(myfile >> bofa >> delimiter >> jp >> delimiter >> wells){
            BOFA.push_back({bofa});
            JP.push_back({jp});
            Wells.push_back({wells});
        }
        cout  << "BOFA" << "   JP" << "   Wells Fargo \n";
        for (size_t x(0); x < BOFA.size(); ++x){
            std::cout << BOFA.at(x) << "\t" << JP.at(x) << "\t" << Wells.at(x) << "\n";
        }
        data.push_back(BOFA);
    	data.push_back(JP);
    	data.push_back(Wells);
    }

    return(data);
}

std::vector<float> gen_vec_from_file(string filename) {
	vector<float> data;
	ifstream myfile(filename);

	if (myfile.is_open()) {
		float val;
		// char delimiter;
		// Read the file.
        myfile.ignore(1000, '\n');
        while(myfile >> val){
            data.push_back({val});
        }
	}

	return data;
}
