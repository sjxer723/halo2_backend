fn BigIsEqual(in0: [Field; 100], in1: [Field; 100]) -> bool {
    let mut sum = 0;

    for i in 0..100 {
        sum = sum + (in0[i] == in1[i]) as Field;
    }
 
    sum == (100 as Field)
}

fn main(in0: [Field; 100], in1: [Field; 100]) {
    assert(BigIsEqual(in0, in1) == true);
}