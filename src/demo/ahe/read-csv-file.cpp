#include <utils/read.h>

int main(){

    // ifstream myfile("loans input nodate.csv"); //file opening constructor
    // //Operation to check if the file opened
    // if ( myfile.is_open() ){
    // 	vector<float> BOFA;
    // 	vector<float> JP;
    // 	vector<float> Wells;

    // 	float bofa, jp, wells;
    // 	char delimiter;
    //     // Read the file.
    //     myfile.ignore(1000, '\n');
    //     while(myfile >> bofa >> delimiter >> jp >> delimiter >> wells){
    //         BOFA.push_back({bofa});
    //         JP.push_back({jp});
    //         Wells.push_back({wells});
    //     }
    //     cout  << "BOFA" << "   JP" << "   Wells Fargo \n";
    //     for (int x(0); x < BOFA.size(); ++x){
    //         std::cout << BOFA.at(x) << "\t" << JP.at(x) << "\t" << Wells.at(x) << "\n";
    //     }
    // }
    // else{
    //     cerr<<"ERROR: The file isnt open.\n";
    // }
    // return 0;

    std::vector< std::vector<float> > data = get_vecs_from_file("loans input nodate.csv");
}

