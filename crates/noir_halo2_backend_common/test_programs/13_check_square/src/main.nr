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
    assert(p != 0);
    assert(s == 0);
}

fn check_square(a: [u4;81]) -> bool {
  let N3 = 9 / 3;
  for i in 0..N3 {
    for j in 0..N3 {
      let mut square = [0;9];
      for u in 0..N3 {
        for v in 0..N3 {
          square[N3*u+v] =a[9*(N3*i+u)+N3*j+v];
        };
      };
      check_cards(square);
    };
  };
 true
}

fn main(a: [u4;81]) {
    check_square(a);
}