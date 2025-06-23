fn multimux1(c0: [Field;100], c1: [Field;100], s: Field) -> [Field; 100]{
    let mut out: [Field; 100] = [0 as Field; 100];

    for i in 0..100 {
        out[i] = (c1[i] - c0[i])*s + c0[i];
    }

    assert (out[99] == 10);

    out
}


fn main(c0: [Field;100], c1: [Field;100], s: Field) {
    multimux1(c0, c1, s);
}