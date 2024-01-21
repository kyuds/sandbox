
struct User {
    active: bool,
    username: String,
    email: String,
    sign_in_count: u64
}

#[derive(Debug)]
struct Rectangle {
    width: u32,
    height: u32
}

fn get_area(r: &Rectangle) -> u32 {
    r.width * r.height
}

impl Rectangle {
    fn area(&self) -> u32 {
        self.width * self.height
    }
    fn create(width: u32, height: u32) -> Self {
        Self { width, height }
    }
}

fn main() {
    let mut user1 = User {
        active: true,
        username: String::from("daniel shin"),
        email: String::from("kyuds@example.com"),
        sign_in_count: 1
    };
    
    println!("{0}", user1.email);

    let rec = Rectangle {
        width: 10,
        height: 5
    };
    println!("Rectangle is {:?}", rec);
    println!("Area of rectangle: {0}", rec.area());

    let square = Rectangle::create(5, 5);
    println!("Created square is {:?}", square);
}

