//! Test-only request draining, extracted from the executor method fixture.
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;
use std::time::Duration;

const MAX_BODY: usize = 1024 * 1024;

pub(crate) fn consume_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    read_request(&mut BufReader::new(stream))
}

fn read_request(reader: &mut impl BufRead) -> String {
    let mut first_line = String::new();
    assert!(reader.read_line(&mut first_line).unwrap() > 0);
    let mut line = String::new();
    let mut content_length = 0usize;
    let mut chunked = false;
    loop {
        line.clear();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap();
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                assert!(value.trim().eq_ignore_ascii_case("chunked"));
                chunked = true;
            }
        }
    }
    // Closing with unread request bytes can reset the client's connection.
    if chunked {
        let mut total = 0usize;
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
            if size == 0 {
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                break;
            }
            assert!(size <= MAX_BODY - total);
            total += size;
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).unwrap();
            let mut terminator = [0; 2];
            reader.read_exact(&mut terminator).unwrap();
            assert_eq!(&terminator, b"\r\n");
        }
    } else {
        assert!(content_length <= MAX_BODY);
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
    }
    first_line
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Fragmented<'a>(Cursor<&'a [u8]>);
    impl Read for Fragmented<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let size = buffer.len().min(3);
            self.0.read(&mut buffer[..size])
        }
    }

    #[test]
    fn fragmented_headers_fixed_body_and_chunked_trailers_are_consumed() {
        for tail in [
            "\r\n",
            "Content-Length: 5\r\n\r\nhello",
            "Transfer-Encoding: chunked\r\n\r\n2;ext=x\r\nhe\r\n3\r\nllo\r\n0\r\nX-Trailer: done\r\n\r\n",
        ] {
            let request = format!("POST /fixture HTTP/1.1\r\nX-Long: {}\r\n{tail}", "x".repeat(5000));
            let mut reader = BufReader::new(Fragmented(Cursor::new(request.as_bytes())));
            assert_eq!(read_request(&mut reader), "POST /fixture HTTP/1.1\r\n");
            assert!(reader.buffer().is_empty());
            assert_eq!(reader.get_ref().0.position(), request.len() as u64);
        }
    }

    #[test]
    #[should_panic]
    fn truncated_body_is_not_accepted_as_a_complete_request() {
        read_request(&mut Cursor::new(
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhi",
        ));
    }

    #[test]
    #[should_panic]
    fn oversized_body_is_rejected_before_allocation() {
        read_request(&mut Cursor::new(
            b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n",
        ));
    }
}
