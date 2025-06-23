fn check_cards(a: [u8;10]) {
    let mut s : Field = 0;
    for k in 1..10+1 {
        let mut p : Field = 1;
  	    for j in 0..10 {
          p = p * (k as Field -  a[j] as Field);
        };
        s = s + p;
    };

    let mut p : Field = 1;
    for j in 0..10-1 {
        p = p * (a[j] as Field);
    };
    assert(p != 0);
    assert(s == 0);
}

fn main(a : [u8; 10]) {
    check_cards(a);
}