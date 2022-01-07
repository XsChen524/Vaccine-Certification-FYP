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

#include "sha256_compression.hpp"
#include "timestamp_circuit.hpp"

using namespace libsnark;
using namespace std;

//Sample inputs
string secretNum;
string timestamp;

//Bit vectors of SHA-256 Digest
libff::bit_vector secNum_bv;
libff::bit_vector timestamp_bv;
libff::bit_vector hash_bv;

int GenerateRandomInt();
string GetTimeStamp();

int main(void)
{   
    secretNum = to_string(GenerateRandomInt());
    timestamp = GetTimeStamp();

    cout << secretNum << endl;
    cout << timestamp << endl;

    //Generator
    libff::print_header("R1CS GG-ppzkSNARK Generator");
    default_r1cs_gg_ppzksnark_pp::init_public_params();        
    typedef default_r1cs_gg_ppzksnark_pp ppzksnark_ppT;
    typedef libff::Fr<ppzksnark_ppT> FieldT;
    typedef sha256_two_to_one_hash_gadget<FieldT> HashT;

    //Initialize bit vectors
    secNum_bv = hash256<HashT>(secretNum);
    timestamp_bv = hash256<HashT>(timestamp);
    hash_bv = hash_two_to_one<HashT>(secNum_bv, timestamp_bv);

        //testing output, comment if no need
        boost::optional<std::string> test_sec_Hex = binToHex<HashT>(secNum_bv);
        boost::optional<std::string> test_timestamp_Hex = binToHex<HashT>(timestamp_bv);
        boost::optional<std::string> test_hash_Hex = binToHex<HashT>(hash_bv);
        cout << "secNum_bv_hex:" << test_sec_Hex<< endl;
        cout << "timestamp_bc_hex:" << test_timestamp_Hex << endl;
        cout << "hash_bv_hex:" << test_hash_Hex << endl;

    Timestamp_Circuit<ppzksnark_ppT> timestamp_circuit;
    r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair = timestamp_circuit.get_keypair();
    
    //Prover
    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof = timestamp_circuit.generate_proof(secNum_bv, timestamp_bv, hash_bv);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    //Verifier
    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = timestamp_circuit.verify_proof(proof, hash_bv);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
    
    return 0;
}

int GenerateRandomInt(){
    srand((unsigned)time(NULL)); 
    return rand();
}

string GetTimeStamp(){
    time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t),"%F %X");
    return ss.str();
}