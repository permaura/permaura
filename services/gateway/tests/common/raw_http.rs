//! The request side of the hand-written HTTP/1.1 upstreams that answer on a raw socket.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

/// Reads one request through the end of its body and returns its head, or `None` if the connection ends first. The body is drained rather than kept, so an allocation meter does not see it, and it is drained at all because a peer that closes with it unread resets the connection on Windows, failing the sender with os error 10053.
pub async fn read_request<S: AsyncRead + Unpin>(sock: &mut S) -> Option<String> {
    let mut reader = BufReader::new(sock);
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if reader.read_until(b'\n', &mut head).await.ok()? == 0 {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let lower = head.to_ascii_lowercase();
    let header = |name: &str| lower.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix(':')).map(str::trim);
    if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        loop {
            let size_line = read_line(&mut reader).await?;
            let size = u64::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
            if size == 0 {
                break;
            }
            drain(&mut reader, size + 2).await?;
        }
        while read_line(&mut reader).await? != "\r\n" {}
    } else if let Some(length) = header("content-length").and_then(|v| v.parse().ok()) {
        drain(&mut reader, length).await?;
    }
    Some(head)
}

async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Option<String> {
    let mut line = Vec::new();
    if reader.read_until(b'\n', &mut line).await.ok()? == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&line).into_owned())
}

async fn drain<R: AsyncBufRead + Unpin>(reader: &mut R, len: u64) -> Option<()> {
    let drained = tokio::io::copy_buf(&mut reader.take(len), &mut tokio::io::sink()).await.ok()?;
    (drained == len).then_some(())
}
