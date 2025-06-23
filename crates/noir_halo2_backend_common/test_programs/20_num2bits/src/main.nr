fn test_to_le_bits(f: Field) {
    let bits = f.to_le_bits(254);
    assert(bits[0] == 0);
}

fn main(f: Field) {
    test_to_le_bits(f);
}