use std::io;

fn main() {
    // variables, shadowing, mutation
    let x = 5;
    let x = x + 1;
    {
        let x = x * 2;
        println!("The value in inner scope: {x}");
    }
    println!("The value in outer scope: {x}");

    // tuples and arrays
    let a: (i32, f64, u8) = (500, 6.4, 1);
    let b = a.1;
    
    println!("{b}");
    
    let arr = [1,2,3,4,5];
    println!("Please enter an array index.");
    let mut index = String::new();
    
    io::stdin()
        .read_line(&mut index)
        .expect("Failed to read line.");

    let index: usize = index
                        .trim()
                        .parse()
                        .expect("Index was not a number.");
    
    let elem = arr[index];

    println!("arr[{index}] = {elem}");
    
    // functions
    another_function();
    print_number(-2);
    
    // expressions
    let exp = {
        let x = 3;
        x + 1
    };
    println!("The value of expression is {exp}");

    let sq = square(5);
    println!("The square of 5 is {sq}");

    // control flow
    let number = 3;
    if (number < 5) && (number > 2) {
        println!("condition was true");
    } else {
        println!("condition was false");
    }

    let condition = true;
    let iflet = if condition { 5 } else { 6 };
    println!("Iflet: {iflet}");

    // loops
    let mut counter = 0;
    let cnt = loop {
        counter += 1;
        
        if counter == 10 {
            break counter * 2;
        }
    };

    println!("Counted: {cnt}");
}

fn another_function() {
    println!("Another function");
}

fn print_number(x: i32) {
    println!("Number is {x}");
}

fn square(x: i32) -> i32 {
    return x * x;
}

