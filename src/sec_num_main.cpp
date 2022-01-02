#include <stdlib.h>
#include <iostream>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <boost/optional.hpp>
#include <boost/optional/optional_io.hpp>

#include "sha256_compression.hpp"
#include "sec_num_circuit.hpp"

using namespace libsnark;
using namespace std;

//Sample inputs
string id = "M123456(7)";
string secretNum = "12345";

//Bit vectors of SHA-256 Digest
libff::bit_vector id_bv;
libff::bit_vector secNum_bv;
libff::bit_vector hash_bv;

int main(void)
{   
    //Generator
    libff::print_header("R1CS GG-ppzkSNARK Generator");
    default_r1cs_gg_ppzksnark_pp::init_public_params();        
    typedef default_r1cs_gg_ppzksnark_pp ppzksnark_ppT;
    typedef libff::Fr<ppzksnark_ppT> FieldT;
    typedef sha256_two_to_one_hash_gadget<FieldT> HashT;

    //Initialize bit vectors
    id_bv = hash256<HashT>(id);
    secNum_bv = hash256<HashT>(secretNum);
    hash_bv = hash_two_to_one<HashT>(id_bv, secNum_bv);

        //testing output, comment if no need
        boost::optional<std::string> test_id_Hex = binToHex<HashT>(id_bv);
        boost::optional<std::string> test_secNum_Hex = binToHex<HashT>(secNum_bv);
        boost::optional<std::string> test_hash_Hex = binToHex<HashT>(hash_bv);
        cout << "id_bv_hex:" << test_id_Hex << endl;
        cout << "secNum_bc_hex:" << test_secNum_Hex << endl;
        cout << "hash_bv_hex:" << test_hash_Hex << endl;

    Sec_Num_Circuit<ppzksnark_ppT> sec_num_circuit;
    r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> keypair = sec_num_circuit.get_keypair();
    
    //Prover
    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof = sec_num_circuit.generate_proof(id_bv, secNum_bv, hash_bv);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    //Verifier
    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = sec_num_circuit.verify_proof(proof, hash_bv);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    return 0;
}