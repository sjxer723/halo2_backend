use dep::std::println;

fn main(mut x: Field, mut y: Field, mut w: Field) {
    let mut x = x as Field;
    let mut y = y as Field;
    let mut z = 0 as Field;

    for i in 0..100 {
        z = x + y;
        x = y;
        y = z;
    };
    assert(x == w);
    
    // println(x);
}