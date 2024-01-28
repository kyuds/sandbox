use std::ops::Deref;
use std::rc::Rc;
use std::cell::RefCell;

enum List {
    Cons(i32, Box<List>),
    Nil,
}

enum RcList {
    Cons(i32, Rc<RcList>),
    Nil,
}

use crate::List::{Cons, Nil};

struct MyBox<T>(T);

impl<T> MyBox<T> {
    fn new(x: T) -> MyBox<T> {
        MyBox(x)
    }
}

impl<T> Deref for MyBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

enum List2 {
    Cons(i32, RefCell<Rc<List>>),
    Nil,
}

impl List2 {
    fn tail(&self) -> Option<&RefCell<Rc<List>>> {
        match self {
            Self::Cons(_, item) => Some(item),
            Self::Nil => None,
        }
    }
}

fn main() {
    let list = Cons(1, Box::new(Cons(2, Box::new(Cons(3, Box::new(Nil))))));

    let x = 5;
    let y = MyBox::new(x);

    assert_eq!(5, x);
    assert_eq!(5, *y);

    let a = Rc::new(RcList::Cons(5, Rc::new(RcList::Cons(10, Rc::new(RcList::Nil)))));
    let b = RcList::Cons(3, Rc::clone(&a));
    let c = RcList::Cons(4, Rc::clone(&a));
}
