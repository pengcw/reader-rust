pub mod crawler;
pub mod executor;
pub mod ffi;
pub mod model;
pub mod parser;
pub mod util;

#[safer_ffi::cfg_headers]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("reader_parser.h")?
        .generate()
}
