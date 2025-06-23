fn has_ship(coord: Field, ship_coords: [Field; 4096]) -> Field {
    let mut collisions = 0;
    for i in 0..4096 {
        collisions = collisions + (ship_coords[i] == coord) as Field;
    };
    collisions
}

fn main(coord: Field, ship_coords: [Field; 4096]) {
  let c = has_ship(coord, ship_coords);
  assert (c == 1);
}