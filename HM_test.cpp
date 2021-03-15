#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

#include "util.hpp"

using namespace libsnark;
using namespace std;

//f(x1,x2)=(x1−8)^2+(x2−3)^3

int main()
{
  typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

  // Initialize the curve parameters

  default_r1cs_ppzksnark_pp::init_public_params();
  
  // Create protoboard

  protoboard<FieldT> pb;

  // Define variables

  pb_variable<FieldT> x1;
  pb_variable<FieldT> T1;
  pb_variable<FieldT> T2;
  pb_variable<FieldT> x2;
  pb_variable<FieldT> T3;
  pb_variable<FieldT> T4;
  pb_variable<FieldT> T5;
  pb_variable<FieldT> out;

  // Allocate variables to protoboard
  // The strings (like "x") are only for debugging purposes
  
  out.allocate(pb, "out");
  x1.allocate(pb, "x2");
  x2.allocate(pb, "x1");
  T1.allocate(pb, "T1");
  T2.allocate(pb, "T2");
  T3.allocate(pb, "T3");
  T4.allocate(pb, "T4");
  T5.allocate(pb, "T5");
  

  // This sets up the protoboard variables
  // so that the first one (out) represents the public
  // input and the rest is private input
  pb.set_input_sizes(1);

  // Add R1CS constraints to protoboard

  // x1-8 = T1
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x1 - 8, 1, T1));

  // T1 * T1 = T2
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(T1, T1, T2));

  // x2 - 3 = T3
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x2 - 3, 1, T3));
  
  // T3 * T3 = T4
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(T3, T3, T4));
  
  // T3 * T4 = T5
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(T3, T4, T5));

  // T5 + T2 = ~out
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(T5 + T2, 1, out));
  
  
  // Add witness values
  pb.val(x1) = 11;
  pb.val(T1) = 3;
  pb.val(T2) = 9;
  pb.val(x2) = 5;
  pb.val(T3) = 2;
  pb.val(T4) = 4;
  pb.val(T5) = 8;
  pb.val(out) = 17;

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

  const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

  print_vk_to_file<default_r1cs_ppzksnark_pp>(vk, "../build/vk_data");
  print_proof_to_file<default_r1cs_ppzksnark_pp>(proof, "../build/proof_data");

  return 0;
}
