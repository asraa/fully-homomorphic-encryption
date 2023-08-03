#ifndef FULLY_HOMOMORPHIC_ENCRYPTION_TRANSPILER_RUST_TFHE_RS_TEMPLATES_H_
#define FULLY_HOMOMORPHIC_ENCRYPTION_TRANSPILER_RUST_TFHE_RS_TEMPLATES_H_

#include "absl/strings/string_view.h"

namespace fhe {
namespace rust {
namespace transpiler {

// Constants used for string templating, these are placed here so the tests
// can reuse them.
constexpr absl::string_view kCodegenTemplate = R"rust(
use rayon::prelude::*;
use std::collections::HashMap;

#[cfg(lut)]
use tfhe::shortint;
#[cfg(lut)]
use tfhe::shortint::prelude::*;
#[cfg(lut)]
use tfhe::shortint::CiphertextBig as Ciphertext;

#[cfg(not(lut))]
use tfhe::boolean::prelude::*;
#[cfg(not(lut))]
use tfhe::boolean::ciphertext::Ciphertext;

#[cfg(fpga)]
use tfhe::boolean::engine::Gate;

#[cfg(lut)]
fn generate_lut(lut_as_int: u64, server_key: &ServerKey) -> shortint::server_key::LookupTableOwned {
    let f = |x: u64| (lut_as_int >> (x as u8)) & 1;
    return server_key.generate_accumulator(f);
}

enum GateInput {
    Arg(usize, usize), // arg + index
    Output(usize), // reuse of output wire
    Tv(usize),  // temp value
    Cst(bool),  // constant
}

use GateInput::*;

// The supported gates for FPGA integration.
#[cfg(fpga)]
enum CellType {
    AND2,
    XOR2,
    OR2,
}

#[cfg(not(any(lut, fpga)))]
enum CellType {
    AND2,
    NAND2,
    XOR2,
    XNOR2,
    OR2,
    NOR2,
    INV,
    IMUX2,
}

#[cfg(lut)]
enum CellType {
    LUT3(u64), // lut_as_int
}

use CellType::*;

$gate_levels

fn prune(temp_nodes: &mut HashMap<usize, Ciphertext>, temp_node_ids: &[usize]) {
  for x in temp_node_ids {
    temp_nodes.remove(&x);
  }
}

pub fn $function_signature {
    #[cfg(lut)]
    let (constant_false, constant_true): (Ciphertext, Ciphertext) = (
      server_key.create_trivial(0), server_key.create_trivial(1));
    #[cfg(not(lut))]
    let (constant_false, constant_true): (Ciphertext, Ciphertext) = (
      server_key.trivial_encrypt(false), server_key.trivial_encrypt(true));

    let args: &[&Vec<Ciphertext>] = &[$ordered_params];

    #[cfg(lut)]
    let luts = {
        let mut luts: HashMap<u64, shortint::server_key::LookupTableOwned> = HashMap::new();
        const LUTS_AS_INTS: [u64; $num_luts] = [$comma_separated_luts];
        for lut_as_int in LUTS_AS_INTS {
            luts.insert(lut_as_int, generate_lut(lut_as_int, server_key));
        }
        luts
    };

    #[cfg(lut)]
    let lut3 = |args: &[&Ciphertext], lut: u64| -> Ciphertext {
        let top_bit = server_key.unchecked_scalar_mul(args[2], 4);
        let middle_bit = server_key.unchecked_scalar_mul(args[1], 2);
        let ct_input = server_key.unchecked_add(&top_bit, &server_key.unchecked_add(&middle_bit, args[0]));
        return server_key.apply_lookup_table(&ct_input, &luts[&lut]);
    };

    let mut temp_nodes = HashMap::new();
    let mut $output_stem = Vec::new();
    $output_stem.resize($num_outputs, constant_false.clone());

    #[cfg(not(fpga))]
    let mut run_level = |
      temp_nodes: &mut HashMap<usize, Ciphertext>,
      tasks: &[((usize, bool, CellType), &[GateInput])]
    | {
        let updates = tasks
            .into_par_iter()
            .map(|(k, task_args)| {
                let (id, is_output, celltype) = k;
                let task_args = task_args.into_iter()
                  .map(|arg| match arg {
                    Cst(false) => &constant_false,
                    Cst(true) => &constant_true,
                    Arg(pos, ndx) => &args[*pos][*ndx],
                    Tv(ndx) => &temp_nodes[ndx],
                    Output(ndx) => &$output_stem[*ndx],
                  }).collect::<Vec<_>>();
                #[cfg(lut)]
                let gate_func = |args: &[&Ciphertext]| match celltype {
                  LUT3(defn) => lut3(args, *defn),
                };
                #[cfg(not(all(lut, fpga)))]
                let gate_func = |args: &[&Ciphertext]| match celltype {
                  AND2 => server_key.and(args[0], args[1]),
                  NAND2 => server_key.nand(args[0], args[1]),
                  OR2 => server_key.or(args[0], args[1]),
                  NOR2 => server_key.nor(args[0], args[1]),
                  XOR2 => server_key.xor(args[0], args[1]),
                  XNOR2 => server_key.xnor(args[0], args[1]),
                  INV => server_key.not(args[0]),
                  IMUX2 => server_key.mux(args[0], args[1], args[2]),
                };
                ((*id, *is_output), gate_func(&task_args))
            })
            .collect::<Vec<_>>();
        updates.into_iter().for_each(|(k, v)| {
            let (index, is_output) = k;
            if is_output {
                $output_stem[index] = v;
            } else {
                temp_nodes.insert(index, v);
            }
        });
    };

    #[cfg(fpga)]
    let mut run_level = |
      temp_nodes: &mut HashMap<usize, Ciphertext>,
      tasks: &[((usize, bool, CellType), &[GateInput])]
    | {
        let mut gates = Vec::<Gate>::new();
        let mut cts_left = Vec::<Ciphertext>::new();
        let mut cts_right = Vec::<Ciphertext>::new();

        // Collect gates, cts_left, and cts_right.
        let updates = tasks
            .iter()
            .map(|(k, task_args)| {
                let (id, is_output, celltype) = k;
                let task_args = task_args.into_iter()
                  .map(|arg| match arg {
                    Cst(false) => &constant_false,
                    Cst(true) => &constant_true,
                    Arg(pos, ndx) => &args[*pos][*ndx],
                    Tv(ndx) => &temp_nodes[ndx],
                    Output(ndx) => &$output_stem[*ndx],
                  }).collect::<Vec<_>>();
                // Note: Only 2-input boolean gates are supported.
                cts_left.push(task_args[0].clone());
                cts_right.push(task_args[1].clone());
                let gate_func = match celltype {
                  AND2 => Gate::AND,
                  OR2 => Gate::OR,
                  XOR2 => Gate::XOR,
                };
                gates.push(gate_func);
                (*id, *is_output)
            })
            .collect::<Vec<_>>();

        // Call gates_packed: linear computation on host device and offload
        // parallel bootstrap operations to FPGA.
        let cts_res = server_key.gates_packed(&gates, &cts_left, &cts_right);

        // Update outputs and temp_nodes by iterating through task IDs.
        updates.iter().enumerate().for_each(|(i, k)| {
            let (index, is_output) = *k;
            if is_output {
                $output_stem[index] = cts_res[i].clone();
            } else {
                temp_nodes.insert(index, cts_res[i].clone());
            }
        });
    };

$run_level_ops

$output_assignment_block

    $return_statement
}
)rust";

// The data of a level's gate ops must be defined statically, or else the
// rustc (LLVM) optimizing passes will take forever.
//
// e.g.,
//
//   const LEVEL_3: [((usize, bool, CellType), &[GateInput]); 8] = [
//       ((1, true, LUT3(6)), &[Arg(0, 0), Arg(0, 1), Cst(false)]),
//       ((2, true, LUT3(120)), &[Arg(0, 0), Arg(0, 1), Arg(0, 2)]),
//       ...
//   ];
//
constexpr absl::string_view kLevelTemplate = R"rust(
static LEVEL_%d: [((usize, bool, CellType), &[GateInput]); %d] = [
%s
];)rust";

// The data specifying, for each LEVEL_K, the set of gate output ids
// that can be safely deleted from memory after LEVEL_K is run.
constexpr absl::string_view kPruneTemplate = R"rust(
static PRUNE_%d: [usize; %d] = [
%s
];)rust";

// A single gate operation defined as constant data
//
//   ((output_id, is_output, LUT3(lut_defn)), &[arglist]),
//
// e.g.,
//
//   ((2, false, LUT3(120)), &[Arg(0, 0), Arg(0, 1), Arg(0, 2)]),
// or
//   ((2, false, AND), &[Arg(0, 0), Arg(0, 1), Arg(0, 2)]),
//
constexpr absl::string_view kTaskTemplate = "    ((%d, %s, %s), &[%s]),";

// The commands used to run the levels defined by kLevelTemplate above.
//
// e.g.,
//
//  run_level(&LEVEL_0);
//  run_level(&LEVEL_1);
//  ...
//
constexpr absl::string_view kRunLevelTemplate =
    "    run_level(&mut temp_nodes, &LEVEL_%d);";

// The commands used to clean up old temp_nodes values that are no longer
// needed. Necessary for large programs with 1M or more gates to conserve RAM.
//
// e.g.,
//
//  run_level(&LEVEL_0);
//  prune(&PRUNE_0);
//  run_level(&LEVEL_1);
//  prune(&PRUNE_1);
//  ...
//
constexpr absl::string_view kRunPruneTemplate =
    "    prune(&mut temp_nodes, &PRUNE_%d);";

// This is needed for the output section of a program,
// when the output values from the yosys netlist must be split off into multiple
// output values for the caller of the code-genned function.
//
// e.g., the following writes the first 16 bits of `out` to an outparameter,
// then returns the remaining bits.
//
//     outputValue[0] = out[0].clone();
//     outputValue[1] = out[1].clone();
//     outputValue[2] = out[2].clone();
//     outputValue[3] = out[3].clone();
//     outputValue[4] = out[4].clone();
//     outputValue[5] = out[5].clone();
//     outputValue[6] = out[6].clone();
//     outputValue[7] = out[7].clone();
//     outputValue[8] = out[8].clone();
//     outputValue[9] = out[9].clone();
//     outputValue[10] = out[10].clone();
//     outputValue[11] = out[11].clone();
//     outputValue[12] = out[12].clone();
//     outputValue[13] = out[13].clone();
//     outputValue[14] = out[14].clone();
//     outputValue[15] = out[15].clone();
//     out = out.split_off(16);
//
constexpr absl::string_view kAssignmentTemplate = "    %s[%d] = %s.clone();";
constexpr absl::string_view kSplitTemplate = "    %s = %s.split_off(%d);";

}  // namespace transpiler
}  // namespace rust
}  // namespace fhe

#endif  // FULLY_HOMOMORPHIC_ENCRYPTION_TRANSPILER_RUST_TFHE_RS_TEMPLATES_H_
