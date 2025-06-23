fn main(inp: Field) {
    let mut lc1 = 0;
    let mut e2 = 0;

    for i in 0..254 {
        let out = shift_and(inp, i as Field); 
        assert(out * (out - 1) == 0);
        lc1 = lc1 * e2;
        e2 = e2 + e2;
    }

    assert (lc1 == in);
}

unconstrained fn shift_and(inp: Field, i: Field) -> Field {
    (inp as U254 >> i) & 1 
}