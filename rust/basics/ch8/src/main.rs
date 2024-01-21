use std::collections::HashMap;

fn main() {
    let v: Vec<i32> = Vec::new();
    let v = vec![1, 2, 3];

    let mut v = Vec::new();
    for i in 5..=8 {
        v.push(i);
    }

    let third: i32 = v[2];
    v.pop();
    println!("The third element is {third}");
    
    let third: Option<&i32> = v.get(2);
    match third {
        Some(third) => println!("The third element is {third}"),
        None => println!("No elem")
    }

    let mut s = String::new();
    let data = "initial_contents";
    let mut s = data.to_string();
    
    s.push_str("bar");
    
    let mut scores = HashMap::new();
    scores.insert(String::from("Blue"), 10);
    scores.insert(String::from("Yellow"), 50);

    let team_name = String::from("Blue");
    let score = scores.get(&team_name).copied().unwrap_or(0);

    for (key, value) in &scores {
        println!("{key}: {value}");
    }
}
