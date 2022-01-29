#define CURVE_ALT_BN128

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <boost/optional.hpp>
#include "../circuit/merklecircuit.h"
#include <stdlib.h>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <string>
#include <time.h>
#include <chrono>
#include <iomanip>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <boost/optional.hpp>
#include <boost/optional/optional_io.hpp>

using namespace libsnark;


template<typename ppzksnark_ppT, typename FieldT, typename HashT>
r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> generate_read_keypair(const size_t tree_depth)
{
    protoboard<FieldT> pb;

    sample::MerkleCircuit<FieldT, HashT> mc(pb, tree_depth);
    mc.generate_r1cs_constraints();
    r1cs_constraint_system<FieldT> cs = pb.get_constraint_system();

    std::cout << "Number of R1CS constraints: " << cs.num_constraints() << std::endl;

    return r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(cs);
}

template<typename ppzksnark_ppT, typename FieldT, typename HashT>
boost::optional<r1cs_gg_ppzksnark_proof<ppzksnark_ppT>> generate_read_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const size_t tree_depth,
                                                                    libff::bit_vector& sk, libff::bit_vector& rk, libff::bit_vector& leaf,
                                                                    libff::bit_vector& root, merkle_authentication_path& path,
                                                                    const size_t address, libff::bit_vector& address_bits)
{
    protoboard<FieldT> pb;

    sample::MerkleCircuit<FieldT, HashT> mc(pb, tree_depth);
    mc.generate_r1cs_constraints();
    mc.generate_r1cs_witness(pb, sk, rk, leaf, root, path, address, address_bits);
    if (!pb.is_satisfied()) {
        std::cout << "pb is not satisfied" << std::endl;
        return boost::none;
    }

    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT, typename FieldT>
bool verify_read_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof, libff::bit_vector& root, libff::bit_vector& rk)
{
    r1cs_primary_input<FieldT> input;
    for (auto i : root) {
        input.push_back(FieldT(i));
    }
    for (auto j : rk) {
        input.push_back(FieldT(j));
    }
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename HashT>
boost::optional<std::string> binToHex(libff::bit_vector& bin) {
    if (bin.size() != HashT::get_digest_len() && bin.size() != HashT::get_digest_len() * 2) {
        std::cout << "The input binary input is not " << HashT::get_digest_len();
        return boost::none;
    }
    std::string res;
    for (int i = 0; i < bin.size(); i += 4) {
        std::string tmp;
        for (int j = i; j < i + 4; j++) {
            tmp.push_back(bin[j] == true ? '1' : '0');
        }
        if (tmp == "0000")
            res.push_back('0');
        else if (tmp == "0001")
            res.push_back('1');
        else if (tmp == "0010")
            res.push_back('2');
        else if (tmp == "0011")
            res.push_back('3');
        else if (tmp == "0100")
            res.push_back('4');
        else if (tmp == "0101")
            res.push_back('5');
        else if (tmp == "0110")
            res.push_back('6');
        else if (tmp == "0111")
            res.push_back('7');
        else if (tmp == "1000")
            res.push_back('8');
        else if (tmp == "1001")
            res.push_back('9');
        else if (tmp == "1010")
            res.push_back('a');
        else if (tmp == "1011")
            res.push_back('b');
        else if (tmp == "1100")
            res.push_back('c');
        else if (tmp == "1101")
            res.push_back('d');
        else if (tmp == "1110")
            res.push_back('e');
        else if (tmp == "1111")
            res.push_back('f');
    }
    return res;
}

std::string hexToChar(const char c) {
    switch(tolower(c))
    {
        case '0': return "0000";
        case '1': return "0001";
        case '2': return "0010";
        case '3': return "0011";
        case '4': return "0100";
        case '5': return "0101";
        case '6': return "0110";
        case '7': return "0111";
        case '8': return "1000";
        case '9': return "1001";
        case 'a': return "1010";
        case 'b': return "1011";
        case 'c': return "1100";
        case 'd': return "1101";
        case 'e': return "1110";
        case 'f': return "1111";
    }
}

libff::bit_vector hexToBin(std::string& str) {
    libff::bit_vector res;
    for (auto item : str) {
        std::string hexItem = hexToChar(item);
        res.push_back(hexItem[0] == '1' ? true : false);
        res.push_back(hexItem[1] == '1' ? true : false);
        res.push_back(hexItem[2] == '1' ? true : false);
        res.push_back(hexItem[3] == '1' ? true : false);
    }
    return res;
}

std::vector<std::string> split(std::string& str, std::string delim) {
    std::vector<std::string> res;
    auto start = 0U;
    auto end = str.find(delim);
    while (end != std::string::npos)
    {
        std::cout << str.substr(start, end - start) << std::endl;
        res.push_back(str.substr(start, end - start));
        start = end + delim.length();
        end = str.find(delim, start);
    }
    return res;
}

template<typename HashT>
libff::bit_vector hash256(std::string str) {
    libff::bit_vector operand;
    for (int i = 0; i < str.size(); i++) {
        char tmpc[5];
        sprintf(tmpc, "%x", str[i]);
        std::string tmps(tmpc);
        libff::bit_vector s = hexToBin(tmps);
        operand.insert(operand.end(), s.begin(), s.end());
    }
    //padding input
    size_t size = operand.size();
    char tmpc[20];
    sprintf(tmpc, "%x", size);
    std::string tmps(tmpc);
    libff::bit_vector s = hexToBin(tmps);
    operand.push_back(1);
    for (int i = size + 1; i < HashT::get_block_len() - s.size(); i++) {
        operand.push_back(0);
    }
    operand.insert(operand.end(), s.begin(), s.end());
    libff::bit_vector res = HashT::get_hash(operand);
    return res;
}

template<typename HashT>
libff::bit_vector hash_two_to_one(libff::bit_vector bv1, libff::bit_vector bv2){
    libff::bit_vector tmp = bv1;
    tmp.insert(tmp.end(), bv2.begin(), bv2.end());
    return HashT::get_hash(tmp);
}


int GenerateRandomInt(){
    srand((unsigned)time(NULL)); 
    return rand();
}

std::string GetTimeStamp(){
    time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t),"%F %X");
    return ss.str();
}


//  ./merkle prove [data1] [data2] [data3] [data4] [data5] [data6] [data7] [data8] [index of the leaf]

int main(int argc, char* argv[]){

    //define the finite field where all our values live, and initialize the curve parameters
    libff::default_ec_pp::init_public_params();        
    typedef libff::default_ec_pp ppzksnark_ppT;
    typedef libff::Fr<ppzksnark_ppT> FieldT;
    typedef sha256_two_to_one_hash_gadget<FieldT> HashT;

    //set the tree_depth, we will extract 8 certificate and prove target certificate is one of the 8, 2^3 = 8
    const size_t tree_depth = 3;

    if (std::string(argv[1]) == "prove"){
        
        /*Set up progress, trust set up*/
        auto keypair = generate_read_keypair<ppzksnark_ppT, FieldT, HashT>(tree_depth); //generate the proving key and verifying key
        std::fstream proving_key("merkle_pk.raw", std::ios_base::out);
        proving_key << keypair.pk;
        proving_key.close();
        std::fstream verifing_key("merkle_vk.raw", std::ios_base::out);
        verifing_key << keypair.vk;
        verifing_key.close();
        /*Comment the line 25-30 if no need store the key*/

        /*Generate the proof*/

        
        //load the pk from file
        std::fstream f_pk("merkle_pk.raw", std::ios_base::in);
        r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> pk;
        f_pk >> pk;
        f_pk.close();
        
        //r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> pk = keypair.pk;

        //define the bit vector, ***merkle tree gadget want target leaf, root,path and address_bits***

        libff::bit_vector leaf, root, address_bits(tree_depth);
        size_t address;
        std::vector<merkle_authentication_node> path(tree_depth);

        //use a 2D array to store the Merkle tree, named levels
        std::vector<std::vector<libff::bit_vector>> levels(tree_depth);

        //define the number of leaf, 8 in our case
        int leaf_count = std::pow(2, tree_depth);

        // testing inputs
        //string secretNum;
        //string timestamp;
        //Bit vectors of SHA-256 Digest
        libff::bit_vector secNum_bv;
        libff::bit_vector rk_bv;
        libff::bit_vector hash_bv;

        std::string secret = "1000";
        std::string random_key = "100";
        secNum_bv = hash256<HashT>(secret);
        rk_bv = hash256<HashT>(random_key);
        hash_bv = hash_two_to_one<HashT>(secNum_bv, rk_bv);
        //secretNum = to_string(GenerateRandomInt());
        //timestamp = GetTimeStamp();

        std::string name[] = { "Jack", "Eric","Allen", "Tom",
                            "Alice","Bob","Cecilia", "Dan" };//Dan won't be used

        // store all the leaf in levels[2], rmb levels is 2Darray
        for (int i = 0; i < leaf_count-1; i++) {
            libff::bit_vector tmp = hash256<HashT>(name[i]);
            std::cout <<*binToHex<HashT>(tmp) << std::endl;
            //std::cout <<"hash"+ i + " : " + *binToHex<HashT>(tmp) << std::endl;
            levels[tree_depth - 1].push_back(tmp);  
        }
        //our target leaf digest add to merkle tree 
        levels[tree_depth - 1].push_back(hash_bv);

        //construct the whole Merkle Tree    **rmb levels[2]= [hash1,hash2,hash3,....]
        /*
                                    root
                                   /    \
                        levels[0][0]     levels[0][1] 
                        /          \                 .
            levels[1][0]            levels[1][1]     . (still has nodes here)   
            /          \                     
    levels[2][0]  levels[2][1] 
        */
        for(int i = tree_depth-1; i >0; i--){
            for (int j = 0; j < levels[i].size(); j += 2) {
                libff::bit_vector input = levels[i][j];   //since hash is a bit vector
                input.insert(input.end(), levels[i][j+1].begin(), levels[i][j+1].end());// so hash2 can be append to hash1
                levels[i-1].push_back(HashT::get_hash(input)); // generate the hash of the intermediate node of upper lebel
            }
        }
        ///find the root hash (Merkle Hash)
        libff::bit_vector input = levels[0][0];
        input.insert(input.end(), levels[0][1].begin(), levels[0][1].end());
        root = HashT::get_hash(input);

        // define the target hash digest , rmb our leaf is added at very last so it is in position 7
        //address = std::stoi(argv[10]);
        address = 7;
        leaf = levels[tree_depth-1][address];   //eg. levels[2][0] the first leaf
        std::cout << address << std::endl;

        /*  reverse order   **I don't understand this part, i guess is for specify RHS or LHS by %2 to see 0 or 1?
            root         to specify the path, if the index is 7, then would be [1,3,7]
              |
            address_bits[2]   
              |
            address_bits[1]   
              |
            address_bits[0]   
        */
        int addr = address;
        for (int i = 0; i < tree_depth; i++) {
            int tmp = (addr & 0x01);
            address_bits[i] = tmp;
            addr = addr / 2;
            std::cout << address_bits[tree_depth-1-i] << std::endl;
        }

        //Fill in the path (Merkle Path, google for better understanding)
        /*          root
                    /  \
            path[0]    node 
                     /   \
                path[1]  node
                         /  \
                    path[2]  node (levels[2][?], eg.the leaf digest we gonna prove)
        */
        size_t index = address;
        for (int i = tree_depth - 1; i >= 0; i--) {
            path[i] = address_bits[tree_depth-1-i] == 0 ? levels[i][index+1] : levels[i][index-1];
            index = index / 2;
        }
        std::cout << "root is " << *binToHex<HashT>(root) << std::endl;

        //Generate Proof
        auto proof = generate_read_proof<ppzksnark_ppT, FieldT, HashT>(pk, tree_depth,secNum_bv,rk_bv, leaf, root, path, address, address_bits);
        if (proof != boost::none) {
            std::cout << "Proof generated!" << std::endl;
        }

        //Save the proof
        std::fstream pr("proof.raw", std::ios_base::out);
        pr << (*proof);
        pr.close();

        //Store the root
        std::fstream rt("root.txt", std::ios_base::out);
        rt << (*binToHex<HashT>(root));
        rt.close();

        //write everything to debug
        std::fstream mk("debug.txt", std::ios_base::out);
        mk << "leaf: " << *(binToHex<HashT>(levels[2][address])) << std::endl; //Write out leaf
        mk << "index: " << address << std::endl;                                //Write out index
        mk << "path: ";                                                        //Write out path
        for (int i = 0; i < path.size(); i++){
            mk << *(binToHex<HashT>(path[i])) << " ";
        };
        mk << std::endl;
        mk << "root: " << *(binToHex<HashT>(root));                             //Write out root
        mk.close();
    }
    if (std::string(argv[1]) == "verify"){
        //load proof
        std::fstream pr("proof.raw", std::ios_base::in);
        r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof;
        pr >> proof;
        pr.close();
	    
        //load vk
        std::fstream vkf("merkle_vk.raw", std::ios_base::in);
        r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> vk;
        vkf >> vk;
        vkf.close();

        //load root
        std::fstream rt("root.txt", std::ios_base::in);
        std::string Merkleroot;
        rt >> Merkleroot;
        rt.close();

        std::string r(Merkleroot);
        libff::bit_vector root = hexToBin(r);
	    
        std::string random_key = "100";
        libff::bit_vector rk_bv = hash256<HashT>(random_key);
        //verify the proof, root is public knowledge, signed by server
        bool ret = verify_read_proof<ppzksnark_ppT, FieldT>(vk, proof, root, rk_bv);
        if (ret) {
            std::cout << "Verification pass!" << std::endl;
        } else {
            std::cout << "Verification failed!" << std::endl;
        }
    }
}
