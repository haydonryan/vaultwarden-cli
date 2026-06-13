use std::fs;

fn cargo_rust_version(cargo_toml: &str) -> &str {
    cargo_toml
        .lines()
        .find_map(|line| {
            line.strip_prefix("rust-version = ")
                .and_then(|value| value.trim().strip_prefix('"'))
                .and_then(|value| value.strip_suffix('"'))
        })
        .expect("Cargo.toml should declare package.rust-version")
}

#[test]
fn readme_source_install_msrv_matches_cargo_rust_version() {
    let cargo_toml = fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    let readme = fs::read_to_string("README.md").expect("read README.md");
    let rust_version = cargo_rust_version(&cargo_toml);

    assert!(
        readme.contains(&format!("Rust {rust_version}+")),
        "README source install docs should mention Rust {rust_version}+ from Cargo.toml"
    );
}
