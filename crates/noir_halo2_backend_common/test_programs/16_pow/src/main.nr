use dep::std::println;


fn pow(x: Field, y: Field) -> Field { // As in tests with minor modifications
    let N_BITS = 254;

    let mut r = 1 as Field;
    let b = y.to_le_bits(N_BITS as u32);
        
    for i in 0..N_BITS {
        r *= r;
        r *= (b[N_BITS - 1 - i] as Field)*x + (1-b[N_BITS - 1 - i] as Field);
    }
    println("y:");
    println(y);
    println("r:");
    println(r);
    r
}

fn main(x: Field) {
    // fix q to be the prime order of the field - 1
    // the following holdß by Fermat's little theorem
    assert (pow(x, -1 as Field) == 1);
}