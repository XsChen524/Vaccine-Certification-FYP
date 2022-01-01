#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

using namespace libsnark;
using namespace std;

int main(void)
{
    libff::start_profiling();
    libff::default_ec_pp::init_public_params();
    test_two_to_one<libff::Fr<libff::default_ec_pp> >();
}
