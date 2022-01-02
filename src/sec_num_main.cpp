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

int main(void)
{
    libff::default_ec_pp::init_public_params();        
    typedef libff::default_ec_pp ppzksnark_ppT;
    typedef libff::Fr<ppzksnark_ppT> FieldT;
    typedef sha256_two_to_one_hash_gadget<FieldT> HashT;

    libff::bit_vector testHash;
    string testInput;
    cout << "Please input text: " << endl;
    cin >> testInput;
    testHash = hash256<HashT>(testInput);
    boost::optional<std::string> testOutput = binToHex<HashT>(testHash);

    cout << testHash.size() << "\n";
    for (size_t i = 0; i < testHash.size(); ++i) {
        cout << testHash[i];
    }
    cout << endl;
    cout << testOutput << endl;

    return 0;
}