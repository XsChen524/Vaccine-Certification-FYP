#ifndef TIMESTAMP_CIRCUIT_HPP
#define TIMESTAMP_CIRCUIT_HPP
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
class Timestamp_Circuit {
    public:
        Timestamp_Circuit();
        r1cs_gg_ppzksnark_keypair<ppT> get_keypair();
        r1cs_gg_ppzksnark_proof<ppT> generate_proof(libff::bit_vector& secNumVector, libff::bit_vector& timestampVector, libff::bit_vector& hashOutVector);
        bool verify_proof(r1cs_gg_ppzksnark_proof<ppT>& proof, libff::bit_vector& hashOutVector);
    private:
        protoboard<libff::Fr<ppT>> pb;
        r1cs_gg_ppzksnark_keypair<ppT> keypair;
        digest_variable<libff::Fr<ppT>> hashOut;
        digest_variable<libff::Fr<ppT>> secNum;
        digest_variable<libff::Fr<ppT>> timestamp;
        sha256_two_to_one_hash_gadget<libff::Fr<ppT>> hash_func;
};

template<typename ppT>
Timestamp_Circuit<ppT>::Timestamp_Circuit(): 
    pb(),
    keypair(),
    hashOut(pb, SHA256_digest_size, "out"),
    timestamp(pb, SHA256_digest_size, "timestamp"), 
    secNum(pb, SHA256_digest_size, "secretNumber"), 
    hash_func(pb, secNum, timestamp, hashOut, "hashF") {
        pb.set_input_sizes(SHA256_digest_size);
        hash_func.generate_r1cs_constraints();
        r1cs_gg_ppzksnark_keypair<ppT> tmp = r1cs_gg_ppzksnark_generator<ppT>(pb.get_constraint_system());
        keypair.pk = tmp.pk;
        keypair.vk = tmp.vk;
    }

template<typename ppT> 
r1cs_gg_ppzksnark_keypair<ppT> Timestamp_Circuit<ppT>::get_keypair() {
  return keypair;
}

template<typename ppT> 
r1cs_gg_ppzksnark_proof<ppT> Timestamp_Circuit<ppT>::generate_proof(libff::bit_vector& secNumVector, libff::bit_vector& timestampVector, libff::bit_vector& hashOutVector) {
  pb.clear_values();
  r1cs_gg_ppzksnark_keypair<ppT> keypair = get_keypair();
  hashOut.generate_r1cs_witness(hashOutVector);
  timestamp.generate_r1cs_witness(timestampVector);
  secNum.generate_r1cs_witness(secNumVector);
  hash_func.generate_r1cs_witness();
  r1cs_primary_input<libff::Fr<ppT>> prim_input = pb.primary_input();
  r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input = pb.auxiliary_input();
  return r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppT> 
bool Timestamp_Circuit<ppT>::verify_proof(r1cs_gg_ppzksnark_proof<ppT>& proof, libff::bit_vector& hashOutVector) {
  pb.clear_values();
  r1cs_gg_ppzksnark_keypair<ppT> keypair = get_keypair();
  r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
  hashOut.generate_r1cs_witness(hashOutVector);
  r1cs_primary_input<libff::Fr<ppT>> prim_input = pb.primary_input();
  return r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, prim_input, proof);
}
#endif
