fn check_cards(a: [u4;9]) {
    let mut s : Field = 0;
    for k in 1..9+1 {
        let mut p : Field = 1;
  	    for j in 0..9 {
          p = p * (k -  a[j] as Field);
        };
        s = s + p;
    };

    let mut p : Field = 1;
    for j in 0..9-1 {
        p = p * (a[j] as Field);
    };
    assert (p != 0);
    assert (s == 0);
}

fn check_column(a: [u4;81]) -> bool {
    for j in 0..9 {
        let mut col = [0;9];
        for i in 0..9 {
          col[i] = a[9*i+j];
        };
        check_cards(col);
    };
 true
}

fn main(x: [u4;81]) {
    check_column(x);
}


