use std::fs::File;
use std::io::{self, Read, ErrorKind};

fn main() {
    // panic_function();

    let greeting_file_result = File::open("hello.txt");
    let greeting_file = match greeting_file_result {
        Ok(file) => file,
        Err(error) => match error.kind() {
            ErrorKind::NotFound => match File::create("hello.txt") {
                Ok(fc) => fc,
                Err(e) => panic!("Problem creating the file: {:?}", e)
            },
            other_error => {
                panic!("Problem opening the file: {:?}", other_error);
            }
        }
    };

    let greeting_file2 = File::open("hello2.txt").unwrap();
    let greeting_file3 = File::open("hello3.txt)
        .expect("hello3.txt isn't present");
    
}

fn panic_function() {
    panic!("crash and burn");
}

fn read_username_from_file() -> Result<String, io::Error> {
    let username_file_result = File::open("hello4.txt");
    
    let mut username_file = match username_file_result {
        Ok(file) => file,
        Err(e) => return Err(e)
    };

    let mut username = String::new();

    match username_file.read_to_string(&mut username) {
        Ok(_) => Ok(username),
        Err(e) => Err(e)
    }
}

fn read_username_from_file_short() -> Result<String, io::Error> {
    let mut username_file = File::open("hello5.txt")?;
    let mut username = String::new();
    username_file.read_to_string(&mut username)?;
    Ok(username)
}

