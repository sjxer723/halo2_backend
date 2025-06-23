use dep::std;


fn didSolve(g: [u8;38], a: [u8; 32]) -> [u8; 3] {
    let mut wrong_guess: u8 = 0;
    let mut contains = false;
    let mut guessed: u8 = 0;
    let mut repeat: u8 = 0;
    for i in 0..38 {
        for j in 0..32 {
            if (g[i] == a[j]) {
                contains = true;
                guessed += 1;
            }
            
        };
        if (!contains) & (guessed < 32) {
            wrong_guess += 1;
        }
        contains = false;
    }
    let g_sort = g.sort();
    for k in 0..37{
        if g_sort[k] == g_sort[k+1]{
            repeat = 1;
        }
    };
    let res = [guessed, wrong_guess, repeat];
    res
}

fn main(guess : [u8; 38], answer : [u8; 32]) {
    let res = didSolve(guess, answer);
    let wrong_input = res[2];
    let solved = res[0];
    let chances_exceeded = res[1];
    
    // We check for three things to decide if the answer is correct:
    // 1. all letters of the answer must have been guessed
    // 2. the prompt guess should not have repeats of any letter
    // 3. no more than 5 mistakes while guessing before the man gets 'hanged'
    assert(! ((solved < 32) | (wrong_input == 1) | (chances_exceeded > 6)));
}