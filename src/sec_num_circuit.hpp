#ifndef PASSWORD_CIRCUIT_HPP_
#define PASSWORD_CIRCUIT_HPP_
#include <iostream>
#include <string>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.tcc>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>

using namespace libsnark;

template<typename ppT>
class Sec_Num_Circuit {
    public:
        Sec_Num_Circuit();
        r1cs_gg_ppzksnark_keypair<ppT> get_keypair();
        r1cs_gg_ppzksnark_proof<ppT> generate_proof(libff::bit_vector& idVector, libff::bit_vector& secNumVector, libff::bit_vector& hashOutVector);
        bool verify_proof(r1cs_gg_ppzksnark_proof<ppT>& proof, libff::bit_vector& hashOutVector);
    private:
        protoboard<libff::Fr<ppT>> pb;
        r1cs_gg_ppzksnark_keypair<ppT> keypair;
        digest_variable<libff::Fr<ppT>> hashOut;
        digest_variable<libff::Fr<ppT>> secNum;
        digest_variable<libff::Fr<ppT>> id;
        sha256_two_to_one_hash_gadget<libff::Fr<ppT>> hash_func;
};

template<typename ppT>
Sec_Num_Circuit<ppT>::Sec_Num_Circuit(): 
    pb(),
    keypair(),
    hashOut(pb, SHA256_digest_size, "out"),
    secNum(pb, SHA256_digest_size, "salt"), 
    id(pb, SHA256_digest_size, "password"), 
    hash_func(pb, id, secNum, hashOut, "hashF") {
        pb.set_input_sizes(SHA256_digest_size);
        hash_func.generate_r1cs_constraints();
        r1cs_gg_ppzksnark_keypair<ppT> tmp = r1cs_gg_ppzksnark_generator<ppT>(pb.get_constraint_system());
        keypair.pk = tmp.pk;
        keypair.vk = tmp.vk;
    }

template<typename ppT> 
r1cs_gg_ppzksnark_keypair<ppT> Sec_Num_Circuit<ppT>::get_keypair() {
  return keypair;
}

template<typename ppT> 
r1cs_gg_ppzksnark_proof<ppT> Sec_Num_Circuit<ppT>::generate_proof(libff::bit_vector& idVector, libff::bit_vector& secNumVector, libff::bit_vector& hashOutVector) {
  pb.clear_values();
  r1cs_gg_ppzksnark_keypair<ppT> keypair = get_keypair();
  hashOut.generate_r1cs_witness(hashOutVector);
  secNum.generate_r1cs_witness(secNumVector);
  id.generate_r1cs_witness(idVector);
  hash_func.generate_r1cs_witness();
  r1cs_primary_input<libff::Fr<ppT>> prim_input = pb.primary_input();
  r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input = pb.auxiliary_input();
  return r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppT> 
bool Password_Circuit<ppT>::verify_proof(r1cs_gg_ppzksnark_proof<ppT>& proof, libff::bit_vector& hashOutVector) {
  pb.clear_values();
  r1cs_gg_ppzksnark_keypair<ppT> keypair = get_keypair();
  r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
  hashOut.generate_r1cs_witness(hashOutVector);
  r1cs_primary_input<libff::Fr<ppT>> prim_input = pb.primary_input();
  return r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, prim_input, proof);
}
#endif
