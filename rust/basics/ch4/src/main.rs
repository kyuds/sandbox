

fn main() {
    let mut s = String::from("hello");
    s.push_str(", world");
    println!("{}", s);

    let s2 = String::from("hello2");
    let s2 = take_and_give_back(s2);

    let length = calculate_string_length(&s2);
    println!("Length: {length}");

    let s3 = String::from("very long string");
    let very = &s3[0..4];
    
}

fn take_and_give_back(s: String) -> String {
    println!("{s}");
    return s;
}

fn calculate_string_length(s: &String) -> usize {
    return s.len();
}
