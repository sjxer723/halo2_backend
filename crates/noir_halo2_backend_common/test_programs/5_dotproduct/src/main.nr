use dep::std::println;
fn main(x : [Field; 4096], y : [Field; 4096], expect: Field) {
    let out = dotproduct(x,y);
    println("x: ");
    println(x);
    println("y: ");
    println(y);
    println("computed dotproduct: ");
    println(out);
    assert(out == expect);
}

fn dotproduct(x : [Field; 4096], y : [Field; 4096]) -> Field {
    let mut out = 0;
    for i in 0..4096 {
        out = out + x[i] * y[i];
    }
    out
}

// testing in nargo
// #[test]
// fn test_main() {
//    assert(dotproduct([1,2],[3,4]) == 11);
//}