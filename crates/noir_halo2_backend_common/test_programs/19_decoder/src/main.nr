fn main(inp: Field) {
    let mut lc = 0;
    for i in 0..32 {
        let out = is_equal(inp, i as Field); 
        assert(out * (inp - i) == 0);
        lc = lc + out;
    }

    let success = lc;
    assert (success * (success - 1) == 0);
}

unconstrained fn is_equal(inp: Field, i: Field) -> Field {
    (inp == i) as Field 
}