use dep::std;

fn gt(a: Field, b: Field) -> bool {
    (a - b) == 0
}

//
//  Checks whether a shot is taken at a coordinate that contains a ship
//
//  Input:
//      lengths { [Field; 5] } - An array containing the length of every ship
//      ships { [Field; 15] } - Array that represents x and y coordinate of ships followed by orientation (horizontal / vertical)
//      shot { [Field; 2] } - Array containing the x and y coordinate of a shot
//
//  Return - A boolean value of whether or not a shot has hit a coordinate occupied by a ship
//
fn check_for_hit(lengths: [Field; 5], ships: [Field; 15], shot: [Field; 2]) -> bool {
    let shot_coord = shot[0] + shot[1] * 10;
    let mut hits = 0;
    for i in 0..5 {
        for j in 0..5 {
            if(gt(lengths[i], j as Field) ) {
                let mut coord = 0;
                if ships[i*3+2] == 1 { 
                    coord = ships[i*3] + ships[i*3+1] * 10 + (10 * j) as Field;
                } else {
                    coord = ships[i*3] + ships[i*3+1] * 10 + j as Field;
                }
                hits = hits + (coord == shot_coord) as u1;
            }
        };
    };
    hits != 0
}

//
//  Circuit to determine shot validity and whether it was a hit or not
//
//  Input:
//      any_hit { u1 } - Report on whether or not shot is a hit
//      ships { [Field: 15] } - Array that represents x and y coordinate of ships followed by orientation (horizontal / vertical) 
//     shot { [Field; 2] } - Array containing the x and y coordinate of a shot
//
fn main(any_hit: u1, ships: [Field; 15], shot: [Field; 2]) {
    // Lengths of all ships
    let lengths: [Field; 5] = [5, 4, 3, 3, 2];
    let mut hits = true;
    // Check whether shot coordinate is a hit or not and then contrain against hit declaration
    hits = check_for_hit(lengths, ships, shot);
    
    assert(hits as u1 == any_hit);
}