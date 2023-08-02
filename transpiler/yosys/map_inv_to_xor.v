// tech mapping module that converts \$not cells to \$xor cells.
//

(* techmap_celltype = "\inv" *)
module map_inverters_to_xor (input A, output Y);
    \xor2 _TECHMAP_REPLACE_(.B(1'b1), .A(A),
            .Y(Y));
endmodule
