#define CURVE_ALT_BN128

#include <stdlib.h>
#include <iostream>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <boost/optional.hpp>
#include <boost/optional/optional_io.hpp>

#include "sha256_compression.hpp"
#include "sec_num_circuit.hpp"

using namespace libsnark;
using namespace std;

//Sample inputs
string sampleId = "M123456(7)";
string sampleSecretNum = "12345";

//Bit vectors of SHA-256 Digest
libff::bit_vector id_bv;
libff::bit_vector secNum_bv;
libff::bit_vector hash_bv;

int main(void)
{   
    //Generator
    libff::default_ec_pp::init_public_params();        
    typedef libff::default_ec_pp ppzksnark_ppT;
    typedef libff::Fr<ppzksnark_ppT> FieldT;
    typedef sha256_two_to_one_hash_gadget<FieldT> HashT;

    //Initialize bit vectors
    id_bv = hash256<HashT>(sampleId);
    secNum_bv = hash256<HashT>(sampleSecretNum);

    //calculate the 2-to-1 hash
    libff::bit_vector tmp = id_bv;
    tmp.insert(tmp.end(), secNum_bv.begin(), secNum_bv.end());
    hash_bv = HashT::get_hash(tmp);

        //testing output, comment if no need
        boost::optional<std::string> test_id_Hex = binToHex<HashT>(id_bv);
        boost::optional<std::string> test_secNum_Hex = binToHex<HashT>(secNum_bv);
        boost::optional<std::string> test_hash_Hex = binToHex<HashT>(hash_bv);
        cout << "id_bv_hex:" << test_id_Hex << endl;
        cout << "secNum_bc_hex:" << test_secNum_Hex << endl;
        cout << "hash_bv_hex:" << test_hash_Hex << endl;

    

    return 0;
}