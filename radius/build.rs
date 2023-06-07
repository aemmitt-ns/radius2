fn main() {
    // if we are building docs, don't build boolector vendor
    if std::env::var("DOCS_RS").is_ok() {
        println!("cargo:rustc-env=BOOLECTOR_NO_VENDOR=1");
    }
}