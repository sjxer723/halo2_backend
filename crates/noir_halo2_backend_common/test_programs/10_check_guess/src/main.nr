use dep::std;

// The server wants to prove to the player that it doesn't cheat
// Each element in solution could be 0 ~ 25
// Each element in guess_result could be 
// 0 - N/A
// 1 - wrong
// 2 - solution contains character but wrong position
// 3 - solution contains character and the position is correct

// Since the solution hash is a public input, the client can verify that the solution on server hasn't changed
// over each round of guess by checking that the solution_hash is consistent in the proof. Additionally, 
// the client can verify that the server compute the correct guess_result by checking the guess and guess_result
// public input in proof.
fn main(solution:[Field;5], guess: [Field;5], guess_result: [Field;5]) {
    for r in 0..10 {
        let guess_result_: [Field;5] = check_guess(solution, guess);
        for i in 0..5 {
            assert(guess_result_[i] == guess_result[i]);
        };
    }
}

fn check_guess(mut solution:[Field;5], mut guess: [Field;5]) -> [Field;5] {
    let mut guess_result: [Field; 5] = [1, 1, 1, 1, 1];

    // constrain solution[0] == guess[0];
    // Check if any guess character is correct
    for i in 0..5 {
        if (solution[i] == guess[i]) {
            guess_result[i] = 3;
            solution[i] = 26; // Mark the solution character as used
            guess[i] = 27; // Mark the guess character as used
        }
    };

    // Check if any guess character is in solution but has incorrect position
    // For some reason, if I nest for-if twice the circuit won't compile in typescript.
    // So I put for loops on the outside
    for i in 0..5 {
        for j in 0..5 {
            if (solution[j] == guess[i]) {
                    guess_result[i] = 2;
                    solution[j] = 26; // Mark the solution character as used
                    guess[i] = 27; // Mark the guess character as used
            }
        };
    };

    guess_result
}