// use generictraits::{ Summary, Tweet };

fn main() {
    // let tweet = Tweet {
    //     username: String::from("horse_ebooks"),
    //     content: String::from(
    //         "of course, as you probably already know, people",
    //     ),
    //     reply: false,
    //     retweet: false,
    // };

    // println!("1 new tweet: {}", tweet.summarize());

    let x = "hello";
    let y = "world!";

    println!("Longer string is: '{}'", longest(x, y));

    let t = Test1::new(String::from("Hi!"));
    t.print();
}

fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() {
        x
    } else {
        y
    }
}

struct Test1 {
    x: String
}

impl Test1 {
    fn new(s: String) -> Self {
        Test1 {
            x: s
        }
    }

    fn print(&self) {
        println!("{}", self.x);
    }
}
