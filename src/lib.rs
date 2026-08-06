pub mod model;
pub mod parser;
pub mod util;
pub mod ffi;

#[safer_ffi::cfg_headers]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("reader_parser.h")?
        .generate()
}
