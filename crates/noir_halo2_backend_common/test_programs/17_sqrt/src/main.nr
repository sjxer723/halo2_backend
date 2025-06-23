use dep::std;

// Field-dependent constant ZETA = a non-square element of Field
// Required for Elligator 2 map
// TODO: Replace with built-in constant.
global ZETA = 5;

// Field-dependent constants for Tonelli-Shanks algorithm (see sqrt function below)
// TODO: Possibly make this built-in.
global C1 = 28;
global C3 = 40770029410420498293352137776570907027550720424234931066070132305055;
global C5 = 19103219067921713944291392827692070036145651957329286315305642004821462161904;


// Boolean indicating whether Field element is a square, i.e. whether there exists a y in Field s.t. x = y*y.
fn is_square(x: Field) -> bool {
    let v = pow(x, 0 - 1/2);

    v*(v-1) == 0
}

// Power function of two Field arguments of arbitrary size.
// Adapted from std::field::pow_32.
fn pow(x: Field, y: Field) -> Field { // As in tests with minor modifications
    let N_BITS = 254;

    let mut r = 1 as Field;
    let b = y.to_le_bits(N_BITS as u32);
        
    for i in 0..N_BITS {
        r *= r;
        r *= (b[N_BITS - 1 - i] as Field)*x + (1-b[N_BITS - 1 - i] as Field);
    }
    
    r
}

// Tonelli-Shanks algorithm for computing the square root of a Field element.
// Requires C1 = max{c: 2^c divides (p-1)}, where p is the order of Field
// as well as C3 = (C2 - 1)/2, where C2 = (p-1)/(2^c1),
// and C5 = ZETA^C2, where ZETA is a non-square element of Field.
// These are pre-computed above as globals.
fn sqrt(x: Field) -> Field {
    let mut z = pow(x, C3);
    let mut t = z*z*x;
    z *= x;
    let mut b = t;
    let mut c = C5;
 
    for i in 0..(C1-1) {
        
        for _j in 1..(C1-i-1) {
            
            b *= b;
            
        }
 
        z *= if b == 1 { 1 } else { c };
 
        c *= c;
 
        t *= if b == 1 { 1 } else { c };
 
        b = t;
    }
    
    z
}

fn main(x: Field) {
    let s = sqrt(x);
    assert(s*s == x);
}