use dep::std;
//
//  Helper function to ensure all ships are within the bounds of the board
//
//  Input:
//      length { u8 } - Length of current ship
//       x { u8 } - x-coord of ship
//       y { u8 } - y-coord of ship
//       z { u8 } - Orientation of ship (horizontal / vertical)
//
fn check_ship_ranges(length: u8, x: u8, y: u8, z: u8) {
    // Constrain z to binary (0 or 1)
    assert(z <= 1);

    // Ensure bounds aren't exceeded in vertical or horizontal orientation
    if z == 1 {
        assert(y + length <= 10);
        assert(x < 10);
    } else {
        assert(x + length <= 10);
        assert(y < 10);
    }
}

//
//  Circuit that determines board validity for a Battleship Game
//
//  Input:
//      hash { pub Field } - Pedersen hash computed outside of circuit that represents board state
//      ships { [Field: 15] } - Array that represents ship coordinates
//
fn main(ships: [Field; 15]) {
    // Lengths of all ships
    let lengths: [u8; 5] = [5, 4, 3, 3, 2];
    // Check ship ranges
    for i in 0..5 {
        check_ship_ranges(lengths[i], ships[i*3] as u8, ships[i*3+1] as u8, ships[i*3+2] as u8);
    };

}