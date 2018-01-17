use std::fmt;

fn main() {
    method_1();
    method_2();
    method_4();
    method_t("text");
}

fn method_1() {
    println!("{}", 1 + 2);
}

fn method_2() {
    println!("{:.1}", 1.0 / 2.0);
    println!("{:.1}", 1.0 / 2.0);
    println!("{:.1}", 1.0 / 2.0);
}

fn method_4() {
    println!("{}", "hi");
}

fn method_t<T: fmt::Debug>(v: T) {
    println!("{:?}", v);
}
