#define CURVE_ALT_BN128

#include <stdlib.h>
#include <iostream>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <boost/optional.hpp>
#include <boost/optional/optional_io.hpp>

using namespace libsnark;
using namespace std;

template<typename HashT> boost::optional<string> binToHex(libff::bit_vector& bin);
string hexToChar(const char c);
libff::bit_vector hexToBin(string& str);
libff::bit_vector hexToBin(string& str);
vector<std::string> split(string& str, string delim);
template<typename HashT>libff::bit_vector hash256(string str);

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

    //cout << testHash.size() << "\n";
    //for (size_t i = 0; i < testHash.size(); ++i) {
    //    cout << testHash[i];
    //}
    //cout << endl;
    cout << testOutput << endl;

    return 0;
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

string hexToChar(const char c) {
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

vector<std::string> split(std::string& str, std::string delim) {
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