
fn sort(words: [Field; 100]) -> Field {
    let mut out = 0;
    let mut sgn = false;
    for val in words {
        if sgn {
            out = out + val;
        } else {
            out = out - val;
        }

        sgn = !sgn;
    }
    assert (out == 50);
    out
}



fn main(words: [Field; 100]) {
    sort(words);
}