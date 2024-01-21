mod front_of_house {
    pub mod hosting {
        pub fn add_to_waitlist() {}
        
        pub fn seat_at_table() {}
    }
    
    pub mod serving {
        pub fn take_order() {}

        pub fn serve_order() {}

        pub fn take_payment() {}
    }
}

pub fn eat_at_restaurant() {
    let mut meal = back_of_house::Breakfast::summer("Rye");
    meal.toast = String::from("Wheat");
    println!("I'd like {} toast please!", meal.toast);
}

mod back_of_house {
    pub struct Breakfast {
        pub toast: String,
        seasonal_fruit: String
    }
    
    impl Breakfast {
        pub fn summer(toast: &str) -> Breakfast {
            Breakfast {
                toast: String::from(str),
                seasonal_fruit: String::from("peaches")
            }
        }
    }
}

