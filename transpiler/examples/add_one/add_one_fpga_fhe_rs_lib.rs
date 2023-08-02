
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


static LEVEL_0: [((usize, bool, CellType), &[GateInput]); 1] = [
    ((0, false, AND2), &[Arg(0, 0), Arg(0, 1)]),
];

static LEVEL_1: [((usize, bool, CellType), &[GateInput]); 1] = [
    ((1, false, AND2), &[Arg(0, 2), Tv(0)]),
];

static LEVEL_2: [((usize, bool, CellType), &[GateInput]); 1] = [
    ((2, false, AND2), &[Arg(0, 3), Tv(1)]),
];

static LEVEL_3: [((usize, bool, CellType), &[GateInput]); 1] = [
    ((3, false, AND2), &[Arg(0, 4), Tv(2)]),
];

static LEVEL_4: [((usize, bool, CellType), &[GateInput]); 1] = [
    ((4, false, AND2), &[Arg(0, 5), Tv(3)]),
];

static LEVEL_5: [((usize, bool, CellType), &[GateInput]); 1] = [
    ((5, false, AND2), &[Arg(0, 6), Tv(4)]),
];

static LEVEL_6: [((usize, bool, CellType), &[GateInput]); 8] = [
    ((0, true, XOR2), &[Arg(0, 0), Cst(true)]),
    ((1, true, XOR2), &[Arg(0, 0), Arg(0, 1)]),
    ((2, true, XOR2), &[Arg(0, 2), Tv(0)]),
    ((3, true, XOR2), &[Arg(0, 3), Tv(1)]),
    ((4, true, XOR2), &[Arg(0, 4), Tv(2)]),
    ((5, true, XOR2), &[Arg(0, 5), Tv(3)]),
    ((6, true, XOR2), &[Arg(0, 6), Tv(4)]),
    ((7, true, XOR2), &[Arg(0, 7), Tv(5)]),
];

static PRUNE_6: [usize; 6] = [
  4,
  0,
  3,
  2,
  5,
  1,
];

fn prune(temp_nodes: &mut HashMap<usize, Ciphertext>, temp_node_ids: &[usize]) {
  for x in temp_node_ids {
    temp_nodes.remove(&x);
  }
}

pub fn add_one(x: &Vec<Ciphertext>, server_key: &ServerKey) -> Vec<Ciphertext> {
    #[cfg(lut)]
    let (constant_false, constant_true): (Ciphertext, Ciphertext) = (
      server_key.create_trivial(0), server_key.create_trivial(1));
    #[cfg(not(lut))]
    let (constant_false, constant_true): (Ciphertext, Ciphertext) = (
      server_key.trivial_encrypt(false), server_key.trivial_encrypt(true));

    let args: &[&Vec<Ciphertext>] = &[x];

    #[cfg(lut)]
    let luts = {
        let mut luts: HashMap<u64, shortint::server_key::LookupTableOwned> = HashMap::new();
        const LUTS_AS_INTS: [u64; 0] = [];
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
    let mut out = Vec::new();
    out.resize(8, constant_false.clone());

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
                    Output(ndx) => &out[*ndx],
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
                out[index] = v;
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
                    Output(ndx) => &out[*ndx],
                  }).collect::<Vec<_>>();
                // Note: Only 2-input boolean gates are supported.
                cts_left.push(*task_args[0]);
                cts_right.push(*task_args[1]);
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
                out[index] = cts_res[i];
            } else {
                temp_nodes.insert(index, cts_res[i]);
            }
        });
    };

    run_level(&mut temp_nodes, &LEVEL_0);
    run_level(&mut temp_nodes, &LEVEL_1);
    run_level(&mut temp_nodes, &LEVEL_2);
    run_level(&mut temp_nodes, &LEVEL_3);
    run_level(&mut temp_nodes, &LEVEL_4);
    run_level(&mut temp_nodes, &LEVEL_5);
    run_level(&mut temp_nodes, &LEVEL_6);
    prune(&mut temp_nodes, &PRUNE_6);



    out
}
