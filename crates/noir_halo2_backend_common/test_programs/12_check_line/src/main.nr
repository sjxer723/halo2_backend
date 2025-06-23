fn check_cards(a: [u8;9]) {
    let mut s : Field = 0;
    for k in 1..9+1 {
        let mut p : Field = 1;
  	    for j in 0..9 {
          p = p * (k as Field -  a[j] as Field);
        };
        s = s + p;
    };

    let mut p : Field = 1;
    for j in 0..9-1 {
        p = p * (a[j] as Field);
    };
    assert(p != 0);
    assert(s == 0);
}

fn check_line(a: [u8;81]) -> bool {
    for i in 0..9 {
      let mut line = [0;9];
        for j in 0..9 {
          line[j] = a[9*i+j];
        };
      check_cards(line);
    };
    true
}

fn main(x: [u8;81]) {
    check_line(x);
}
