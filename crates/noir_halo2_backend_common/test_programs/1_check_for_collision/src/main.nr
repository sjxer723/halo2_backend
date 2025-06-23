fn has_ship(coord: Field, ship_coords: [Field; 25]) -> Field {
    let mut collisions = 0;
    for i in 0..25 {
        collisions = collisions + (ship_coords[i] == coord) as Field;
    };
    collisions
}

fn check_for_collision(lengths: [u8; 5], ships: [Field; 15]) {
    let mut collisions = 0;
    // Array is initialized to length 25 because array indices in Noir are currently restricted
    // to comptime values. Length 25 ensures index never exceeds array bounds (index max (i * 5 + j) is 24)
    let mut ship_coords: [Field; 25] = [100; 25];
    for i in 0..5 {
        //
        //  Inner loop will eventually have range determined by ship length (0..lengths[i]).
        //  For now non comptime indexes are not supported in ranges. Set to 5 since maximum
        //  ship length is 5
        //
        for j in 0..5 {
            // Prevent array from being mutated if inner loop index exceeds current ship length
            if(lengths[i] > j as u8) {
                let mut coord = 0;
                let index = i * 5 + j;
                // If ship is oriented vertically then calculate coordinate accordingly. Same for horizontal
                if ships[i*3+2] == 1 { 
                    coord = ships[i*3] + ships[i*3+1] * (10 as Field) + ((10 * j) as Field);
                } else {
                    coord = ships[i*3] + ships[i*3+1] * (10 as Field) + (j as Field);
                }
                collisions = collisions + has_ship(coord, ship_coords);
                ship_coords[index] = coord;
            }
        };
    };
    assert(collisions == 0);
}

fn main(lengths: [u8; 5], ships: [Field; 15]) {
    for r in 0..5 {
        check_for_collision(lengths, ships);
    }
}