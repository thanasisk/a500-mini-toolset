# a500-mini-toolset
## A Firmware decryptor for the A500 mini
Why? Because Rust ...
## Prerequisites
Just standard recent Rust toolchain
## What it does, what it does not.
It decrypts firmware *updates* you can get from the [support site](https://retrogames.biz/support/thea500-mini/upgrade/)
Getting the actual firmware off the A500-mini requires UART access and currently is *not* part of the functionality this toolkit offers.
## Building
- Assuming you have a working Rust toolchain `cargo build` should do the trick.
- Once fetching of crates and compilation is complete navigate to `target` and locate your binary
- The above would make a debug build - unoptimized and with debug symbols. I can live with this, if you need more speed, read up on `cargo build --release`.
## Usage
Using the toolkit is quite simple. To list contents `./a500-mini-toolset <YOUR_FIRMWARE_FILE>` - if you want to extract, create a directory called `dumpdir` in the same location as the `a500-mini-toolset` executable.
## Performance comparison
- debug build: `./a500-mini-toolset theA500-mini-upgrade-v1.2.1.a5u  11.20s user 0.15s system 99% cpu 11.387 total`
- release build: `./a500-mini-toolset theA500-mini-upgrade-v1.2.1.a5u  0.25s user 0.15s system 98% cpu 0.405 total`
## Greetz
- [Ole,a mental giant, who beat me in reversing ...](https://github.com/oleavr)
## LICENSE
MIT
