pub mod crawler;
pub mod executor;
pub mod ffi;
pub mod host_services;
pub mod model;
pub mod parser;
pub mod util;

// ring's ARM/Linux detector imports getauxval, absent from Kindle's EGLIBC 2.12.
// Return no optional HWCAPs so ring uses its portable crypto implementation.
#[cfg(all(
    feature = "kindle-eglibc-2-12",
    target_arch = "arm",
    target_abi = "eabi",
    target_os = "linux",
    target_env = "gnu",
))]
core::arch::global_asm!(
    ".syntax unified",
    ".text",
    ".weak getauxval",
    ".type getauxval, %function",
    "getauxval:",
    "movs r0, #0",
    "bx lr",
    ".size getauxval, .-getauxval",
);

#[safer_ffi::cfg_headers]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("reader_parser.h")?
        .generate()
}
