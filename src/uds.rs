//! Minimal HTTP/1.1 client over a Unix domain socket.
//!
//! The Confidential Space launcher exposes its token API only on
//! `/run/container_launcher/teeserver.sock`, and `reqwest` cannot speak to a
//! Unix socket. Rather than add an async HTTP stack for one request to one
//! known local endpoint, this speaks just enough HTTP/1.1 to make it — which
//! also means the response body lands directly in a [`SecretBuffer`] instead
//! of in some library's internal allocation.
//!
//! Scope: one request, `Connection: close`, `Content-Length` or chunked. It is
//! not a general-purpose client and should not be reused as one.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::secret::SecretBuffer;

/// Cap on the launcher's response. Confidential Space tokens run to a few KiB.
const MAX_RESPONSE: usize = 64 * 1024;

pub struct UdsResponse {
    pub status: u16,
    pub body: SecretBuffer,
}

/// POST `body` as JSON to `path` on the socket at `socket`.
pub fn post_json(socket: &Path, path: &str, body: &[u8], timeout: Duration) -> Result<UdsResponse> {
    let mut stream = UnixStream::connect(socket).map_err(|e| Error::Io(e.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| Error::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| Error::Io(e.to_string()))?;

    // `Connection: close` makes the server signal end-of-body by closing, so
    // we never have to deal with keep-alive framing.
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|e| Error::Io(e.to_string()))?;
    stream
        .write_all(body)
        .map_err(|e| Error::Io(e.to_string()))?;
    stream.flush().map_err(|e| Error::Io(e.to_string()))?;

    // The whole response, headers included, is read into locked memory: the
    // body is a bearer credential.
    let mut raw = SecretBuffer::new(MAX_RESPONSE)?;
    raw.fill_from(&mut stream)?;

    parse_response(raw.as_slice())
}

fn parse_response(raw: &[u8]) -> Result<UdsResponse> {
    let header_end = find(raw, b"\r\n\r\n").ok_or(Error::MalformedResponse {
        context: "attestation launcher",
    })?;
    let head = &raw[..header_end];
    let body = &raw[header_end + 4..];

    let mut lines = head.split(|&b| b == b'\n');
    let status_line = lines.next().ok_or(Error::MalformedResponse {
        context: "attestation launcher",
    })?;
    let status = parse_status(status_line)?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        // Header names are case-insensitive, so compare lowercased.
        if let Some((name, value)) = split_header(line.trim_ascii()) {
            match name.as_str() {
                "content-length" => {
                    content_length = value.trim().parse::<usize>().ok();
                }
                "transfer-encoding" => {
                    chunked = value.to_ascii_lowercase().contains("chunked");
                }
                _ => {}
            }
        }
    }

    let mut out = SecretBuffer::new(MAX_RESPONSE)?;
    if chunked {
        // Go's net/http omits Content-Length when it streams, so this is a
        // real possibility rather than a theoretical one.
        decode_chunked(body, &mut out)?;
    } else {
        let end = match content_length {
            // A declared length longer than what arrived means a truncated
            // token; accepting it would produce a confusing downstream error.
            Some(n) if n > body.len() => {
                return Err(Error::MalformedResponse {
                    context: "attestation launcher",
                });
            }
            Some(n) => n,
            None => body.len(),
        };
        out.push(&body[..end])?;
    }
    Ok(UdsResponse { status, body: out })
}

/// `HTTP/1.x <code> <reason>` → `<code>`.
fn parse_status(status_line: &[u8]) -> Result<u16> {
    let bad = Error::MalformedResponse {
        context: "attestation launcher",
    };
    let line = status_line.trim_ascii();
    if !line.starts_with(b"HTTP/1.") {
        return Err(bad);
    }
    line.split(|&b| b == b' ')
        .nth(1)
        .and_then(|code| core::str::from_utf8(code).ok())
        .and_then(|code| code.parse().ok())
        .ok_or(bad)
}

fn split_header(line: &[u8]) -> Option<(String, String)> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = core::str::from_utf8(&line[..colon])
        .ok()?
        .trim()
        .to_ascii_lowercase();
    let value = core::str::from_utf8(&line[colon + 1..])
        .ok()?
        .trim()
        .to_string();
    Some((name, value))
}

fn decode_chunked(mut body: &[u8], out: &mut SecretBuffer) -> Result<()> {
    let bad = || Error::MalformedResponse {
        context: "attestation launcher",
    };
    loop {
        let line_end = find(body, b"\r\n").ok_or_else(bad)?;
        let size_line = &body[..line_end];
        // Strip any chunk extensions after ';'.
        let size_hex = size_line.split(|&b| b == b';').next().ok_or_else(bad)?;
        let size = core::str::from_utf8(size_hex.trim_ascii())
            .ok()
            .and_then(|hex| usize::from_str_radix(hex, 16).ok())
            .ok_or_else(bad)?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(());
        }
        if size > body.len() {
            return Err(bad());
        }
        out.push(&body[..size])?;
        // Skip the chunk's data and its trailing CRLF.
        body = body.get(size + 2..).ok_or_else(bad)?;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nabcde";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body.as_slice(), b"abcde");
    }

    #[test]
    fn ignores_trailing_bytes_beyond_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcXXXX";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body.as_slice(), b"abc");
    }

    #[test]
    fn rejects_truncated_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nabc";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body.as_slice(), b"hello world");
    }

    #[test]
    fn parses_chunked_with_extensions() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    3;name=value\r\nabc\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body.as_slice(), b"abc");
    }

    #[test]
    fn header_matching_is_case_insensitive() {
        let raw = b"HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 2\r\n\r\nhi";
        assert_eq!(parse_response(raw).unwrap().body.as_slice(), b"hi");
        let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().body.as_slice(), b"hi");
    }

    #[test]
    fn surfaces_error_status() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().status, 403);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_response(b"not http at all").is_err());
        assert!(parse_response(b"GARBAGE 200 OK\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_lying_chunk_size() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFF\r\nshort\r\n0\r\n\r\n";
        assert!(parse_response(raw).is_err());
    }
}
