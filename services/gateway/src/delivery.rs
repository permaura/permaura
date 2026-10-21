//! Holding an execution's capacity until its response has been sent, not merely built.
//!
//! An execution route's response is the redacted view of an upstream document, and it can be several times that document's size. hyper keeps the body until the client reads it, so a slot released the moment the response object existed bounded executions but not deliveries: an agent reading its responses slowly could keep any number of them in memory with no slot held. [`hold_until_sent`] moves the slot into the body, so a slow reader spends slots rather than memory, and gives the slot and the unsent bytes back at a deadline a stalled reader cannot extend.

use std::any::Any;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use axum::body::{Body, Bytes, HttpBody};
use axum::response::Response;
use axum::BoxError;
use http_body::{Frame, SizeHint};
use tokio::task::AbortHandle;

/// The largest piece handed to hyper at once (64 KiB). Each piece is a copy, never a slice of the response's buffer, because a slice keeps the whole buffer alive: once the last piece is handed over the buffer is already freed, and hyper holds at most [`STALLED_COPY_BYTES`] of copies.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// The most of a response hyper keeps queued for a connection whose client has stopped reading (about 472 KiB): it polls the body while its write buffer holds less than its default 408 KiB (`8192 + 4096 * 100` in hyper 1.x, which `axum::serve` does not change), so one piece past that. A body past its delivery deadline frees everything else, but these copies stay until the connection closes.
pub const STALLED_COPY_BYTES: usize = 8192 + 4096 * 100 + CHUNK_BYTES;

/// The slowest a reader may take a response and still be sure of all of it, for a response up to 15 MiB (128 KiB a second, about 1 Mbit/s): the delivery deadline grows with a response's length at this rate only until it reaches [`DELIVERY_CAP`], which this rate fills at 15 MiB, so the reader of a longer response needs to read at its length over 120 s (over the floor, when that is longer).
/// The defaults reach that: the longest `/v1/invoke` view, 3.8 x 5 MiB (19 MiB), needs about 162 KiB a second, and a `/mcp` answer carries its view twice, so one whose view passes about 7.5 MiB passes 15 MiB; with `PERMAURA_HTTP_MAX_RESPONSE_BYTES` raised, ordinary responses pass it too.
pub const DELIVERY_MIN_RATE: u64 = 128 * 1024;

/// The longest the delivery deadline grows to (120s), under the 130 seconds after which Cloud Run's frontend closes a hosted worker's connection anyway.
pub const DELIVERY_CAP: Duration = Duration::from_secs(120);

/// How long a response of `len` bytes may take to be sent: `floor`, grown with the length at [`DELIVERY_MIN_RATE`] up to [`DELIVERY_CAP`] (or to `floor`, when that is longer), and the cap when the length is not known exactly.
pub fn delivery_deadline(floor: Duration, len: Option<u64>) -> Duration {
    let cap = DELIVERY_CAP.max(floor);
    match len {
        Some(len) => Duration::from_millis(len.saturating_mul(1_000) / DELIVERY_MIN_RATE).clamp(floor, cap),
        None => cap,
    }
}

/// Guards a handler wants held until its response has been sent rather than built, attached to the response; the execution middleware takes them off it and holds them beside the execution slot.
#[derive(Clone, Default)]
pub struct HoldWhileSending(Vec<Arc<dyn Any + Send + Sync>>);

impl HoldWhileSending {
    /// Hold `guard` until `response` has been sent, when it leaves through an execution route.
    pub fn attach<G: Send + Sync + 'static>(response: &mut Response, guard: G) {
        let extensions = response.extensions_mut();
        match extensions.get_mut::<HoldWhileSending>() {
            Some(hold) => hold.0.push(Arc::new(guard)),
            None => {
                extensions.insert(HoldWhileSending(vec![Arc::new(guard)]));
            }
        }
    }
}

/// Replace `response`'s body with one that owns `guard` until the last byte has been handed to hyper, the client hangs up, or the delivery deadline passes, whichever is first: [`delivery_deadline`] for `floor` and the body's exact length, or the length its Content-Length header declares when the body is a stream that does not know it.
///
/// At the deadline the guard and every unsent byte are dropped at once, without waiting for hyper to poll again (it does not poll a body while its client is not reading), and the next poll fails so hyper closes the connection mid-body: a client sees a short body, never a well-formed truncated document. A `floor` of `None` holds the guard until the body is sent or the connection closes.
pub fn hold_until_sent<G: Send + 'static>(response: Response, guard: G, floor: Option<Duration>) -> Response {
    wrap(response, guard, floor).0
}

fn wrap<G: Send + 'static>(response: Response, guard: G, floor: Option<Duration>) -> (Response, Option<AbortHandle>) {
    let (parts, inner) = response.into_parts();
    let len = inner.size_hint().exact().or_else(|| declared_len(&parts.headers));
    let deadline = floor.map(|floor| delivery_deadline(floor, len));
    let shared = Arc::new(Mutex::new(Shared {
        live: Some(Live { inner, pending: Bytes::new(), _guard: Box::new(guard) }),
        waker: None,
    }));
    let watchdog = deadline.map(|deadline| tokio::spawn(expire(Arc::downgrade(&shared), deadline)).abort_handle());
    let handle = watchdog.clone();
    (Response::from_parts(parts, Body::new(Delivery { shared, watchdog, finished: false })), handle)
}

/// The length a response declares in its Content-Length header: a document written as a stream knows its length only there ([`crate::memory::streamed_response`]).
fn declared_len(headers: &axum::http::HeaderMap) -> Option<u64> {
    headers.get(axum::http::header::CONTENT_LENGTH)?.to_str().ok()?.trim().parse().ok()
}

struct Live {
    inner: Body,
    /// What is left of the inner body's last data frame.
    pending: Bytes,
    _guard: Box<dyn Any + Send>,
}

struct Shared {
    /// `None` once the deadline has taken it.
    live: Option<Live>,
    /// The task last left waiting on the inner body, woken when the deadline takes the body away so its connection fails now rather than never.
    waker: Option<Waker>,
}

/// The body [`hold_until_sent`] puts on a response.
struct Delivery {
    shared: Arc<Mutex<Shared>>,
    watchdog: Option<AbortHandle>,
    finished: bool,
}

#[derive(Debug)]
struct DeliveryExpired;

impl std::fmt::Display for DeliveryExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the response was not read within the gateway's delivery deadline")
    }
}

impl std::error::Error for DeliveryExpired {}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(|e| e.into_inner())
}

async fn expire(shared: Weak<Mutex<Shared>>, deadline: Duration) {
    tokio::time::sleep(deadline).await;
    let Some(shared) = shared.upgrade() else { return };
    let (live, waker) = {
        let mut shared = lock(&shared);
        (shared.live.take(), shared.waker.take())
    };
    let Some(live) = live else { return };
    let unsent_bytes = (live.pending.len() as u64).saturating_add(live.inner.size_hint().lower());
    drop(live);
    if let Some(waker) = waker {
        waker.wake();
    }
    tracing::warn!(
        timeout_ms = deadline.as_millis() as u64,
        unsent_bytes,
        "an execution response was not read within the gateway's delivery timeout; its slot and unsent bytes were released and the connection will be closed"
    );
}

impl Delivery {
    fn finish(&mut self) {
        self.finished = true;
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.abort();
        }
    }
}

impl HttpBody for Delivery {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        let mut shared = lock(&this.shared);
        let Shared { live: slot, waker } = &mut *shared;
        let Some(live) = slot.as_mut() else {
            drop(shared);
            this.finish();
            return Poll::Ready(Some(Err(Box::new(DeliveryExpired))));
        };
        let polled = loop {
            if !live.pending.is_empty() {
                let n = live.pending.len().min(CHUNK_BYTES);
                let piece = Bytes::copy_from_slice(&live.pending[..n]);
                live.pending = live.pending.slice(n..);
                break Some(Ok(Frame::data(piece)));
            }
            match Pin::new(&mut live.inner).poll_frame(cx) {
                Poll::Pending => {
                    *waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                Poll::Ready(None) => break None,
                Poll::Ready(Some(Err(e))) => break Some(Err(BoxError::from(e))),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => live.pending = data,
                    Err(trailers) => break Some(Ok(trailers)),
                },
            }
        };
        let done = match &polled {
            Some(Ok(_)) => live.pending.is_empty() && live.inner.is_end_stream(),
            None | Some(Err(_)) => true,
        };
        if done {
            let released = slot.take();
            *waker = None;
            drop(shared);
            drop(released);
            this.finish();
        }
        Poll::Ready(polled)
    }

    fn is_end_stream(&self) -> bool {
        if self.finished {
            return true;
        }
        // Not ended once the deadline has taken the body, so hyper polls once more and fails the connection; ended, a chunked body would close as if it were whole.
        lock(&self.shared).live.as_ref().is_some_and(|live| live.pending.is_empty() && live.inner.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        if self.finished {
            return SizeHint::with_exact(0);
        }
        let shared = lock(&self.shared);
        let Some(live) = shared.live.as_ref() else { return SizeHint::default() };
        let inner = live.inner.size_hint();
        let pending = live.pending.len() as u64;
        let mut hint = SizeHint::new();
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(pending));
        }
        hint.set_lower(inner.lower().saturating_add(pending));
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    use axum::http::HeaderMap;
    use tokio::sync::Semaphore;

    fn document(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// One execution slot, taken, and the semaphore that shows whether it is still held.
    fn slot() -> (Arc<Semaphore>, tokio::sync::OwnedSemaphorePermit) {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().expect("a free slot");
        (slots, permit)
    }

    async fn next(body: &mut Body) -> Option<Result<Frame<Bytes>, axum::Error>> {
        poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await
    }

    #[tokio::test]
    async fn a_body_larger_than_a_piece_arrives_whole_with_its_exact_length() {
        let sent = Bytes::from(document(5 * CHUNK_BYTES + 123));
        let (_slots, permit) = slot();
        let response = hold_until_sent(Response::new(Body::from(sent.clone())), permit, Some(Duration::from_secs(30)));
        let mut body = response.into_body();
        assert_eq!(body.size_hint().exact(), Some(sent.len() as u64), "hyper writes the same Content-Length as before");
        assert!(!body.is_end_stream());
        // Kept, as hyper keeps the pieces it has queued but not yet written.
        let mut pieces = Vec::new();
        while let Some(frame) = next(&mut body).await {
            let data = frame.expect("no error").into_data().expect("a data frame");
            assert!(data.len() <= CHUNK_BYTES, "every piece is at most {CHUNK_BYTES} bytes");
            pieces.push(data);
        }
        assert_eq!(pieces.len(), 6);
        assert_eq!(pieces.concat(), sent, "byte-identical");
        assert!(body.is_end_stream());
        assert!(sent.is_unique(), "the pieces are copies, so the response's own buffer is already freed while they wait to be written");
    }

    #[tokio::test]
    async fn the_slot_is_held_until_the_last_piece_and_released_with_it() {
        let sent = document(3 * CHUNK_BYTES + 1);
        let (slots, permit) = slot();
        let mut body = hold_until_sent(Response::new(Body::from(sent)), permit, Some(Duration::from_secs(30))).into_body();
        for piece in 0..3 {
            next(&mut body).await.expect("a piece").expect("no error");
            assert_eq!(slots.available_permits(), 0, "held after piece {piece} of 4");
        }
        assert!(!body.is_end_stream());
        next(&mut body).await.expect("the last piece").expect("no error");
        assert_eq!(slots.available_permits(), 1, "released as the last piece is handed over");
        assert!(body.is_end_stream(), "so hyper ends the body with that piece");
        assert!(next(&mut body).await.is_none());
    }

    #[tokio::test]
    async fn a_body_dropped_part_way_releases_the_slot() {
        let (slots, permit) = slot();
        let mut body = hold_until_sent(Response::new(Body::from(document(4 * CHUNK_BYTES))), permit, Some(Duration::from_secs(30))).into_body();
        next(&mut body).await.expect("a piece").expect("no error");
        assert_eq!(slots.available_permits(), 0);
        drop(body);
        assert_eq!(slots.available_permits(), 1, "a client that hung up gives the slot back");
    }

    #[tokio::test]
    async fn an_unread_body_gives_back_its_slot_and_its_bytes_at_the_deadline_and_then_fails() {
        let sent = Bytes::from(document(2 * CHUNK_BYTES));
        let (slots, permit) = slot();
        let floor = Duration::from_millis(500);
        let deadline = delivery_deadline(floor, Some(sent.len() as u64));
        assert_eq!(deadline, Duration::from_secs(1), "128 KiB at the minimum rate, above the floor");
        let started = std::time::Instant::now();
        let mut body = hold_until_sent(Response::new(Body::from(sent.clone())), permit, Some(floor)).into_body();
        // One piece taken, as hyper does before its write buffer fills and it stops polling.
        next(&mut body).await.expect("a piece").expect("no error");
        assert_eq!(slots.available_permits(), 0, "held while the body waits to be read");
        assert!(!sent.is_unique(), "and the body still holds the response's buffer");
        tokio::time::timeout(Duration::from_secs(10), async {
            while slots.available_permits() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the deadline released the slot with the body never polled again");
        assert!(started.elapsed() >= deadline, "and not before the deadline");
        assert!(sent.is_unique(), "the unsent bytes went with it");
        assert!(!body.is_end_stream(), "never reported as a whole body");
        let failed = next(&mut body).await.expect("a frame").expect_err("the next poll fails, so hyper closes the connection");
        assert!(failed.to_string().contains("delivery deadline"), "{failed}");
        assert!(next(&mut body).await.is_none());
    }

    #[tokio::test]
    async fn a_body_sent_in_full_cancels_its_deadline() {
        let (slots, permit) = slot();
        let (response, watchdog) = wrap(Response::new(Body::from(document(2 * CHUNK_BYTES))), permit, Some(Duration::from_secs(30)));
        let watchdog = watchdog.expect("a deadline spawns a watchdog");
        let mut body = response.into_body();
        next(&mut body).await.expect("a piece").expect("no error");
        tokio::task::yield_now().await;
        assert!(!watchdog.is_finished(), "a body still being sent keeps its deadline");
        while next(&mut body).await.is_some() {}
        assert_eq!(slots.available_permits(), 1);
        // Thirty seconds away, so only the abort can have finished it.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !watchdog.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the watchdog was aborted when the last piece went");
        drop(body);
    }

    /// The execution routes write their documents as a stream whose length is declared in Content-Length rather than in the body's size hint ([`crate::memory::streamed_response`]); without the header's length every such response got the 120 s cap.
    #[tokio::test]
    async fn a_streamed_body_takes_its_deadline_from_the_length_it_declares() {
        let sent = Bytes::from(document(2 * CHUNK_BYTES));
        let response = crate::memory::streamed_response(axum::http::StatusCode::OK, sent.len(), vec![sent.clone()].into_iter());
        assert_eq!(response.body().size_hint().exact(), None, "the stream does not know its length");
        let (slots, permit) = slot();
        let floor = Duration::from_millis(500);
        let started = std::time::Instant::now();
        let mut body = hold_until_sent(response, permit, Some(floor)).into_body();
        next(&mut body).await.expect("a piece").expect("no error");
        assert_eq!(slots.available_permits(), 0);
        tokio::time::timeout(Duration::from_secs(10), async {
            while slots.available_permits() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("released at the 1 s its declared 128 KiB sets, not at the 120 s cap");
        assert!(started.elapsed() >= Duration::from_secs(1), "and not before it");
    }

    #[test]
    fn a_declared_length_is_read_only_when_it_is_one_number() {
        let mut response = Response::new(Body::from_stream(futures_util::stream::empty::<Result<Bytes, std::convert::Infallible>>()));
        response.headers_mut().insert(axum::http::header::CONTENT_LENGTH, "12, 12".parse().unwrap());
        assert_eq!(declared_len(response.headers()), None);
        response.headers_mut().insert(axum::http::header::CONTENT_LENGTH, "131072".parse().unwrap());
        assert_eq!(declared_len(response.headers()), Some(131_072));
    }

    /// A source of a known small length that never produces anything and never wakes its reader.
    struct Stalled;

    impl HttpBody for Stalled {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Pending
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(1024)
        }
    }

    #[tokio::test]
    async fn a_body_waiting_on_its_source_is_woken_to_fail_at_the_deadline() {
        let (slots, permit) = slot();
        let mut body = hold_until_sent(Response::new(Body::new(Stalled)), permit, Some(Duration::from_millis(200))).into_body();
        let polled = tokio::time::timeout(Duration::from_secs(5), next(&mut body))
            .await
            .expect("woken at the deadline rather than left waiting on a source that never wakes it");
        polled.expect("a frame").expect_err("which is the failure");
        assert_eq!(slots.available_permits(), 1);
    }

    /// One data frame, then trailers.
    struct WithTrailers {
        data: Option<Bytes>,
        trailers: Option<HeaderMap>,
    }

    impl HttpBody for WithTrailers {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            if let Some(data) = this.data.take() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
            Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))))
        }

        fn is_end_stream(&self) -> bool {
            self.data.is_none() && self.trailers.is_none()
        }
    }

    #[tokio::test]
    async fn an_empty_body_is_ended_at_once_and_releases_on_drop() {
        let (slots, permit) = slot();
        let body = hold_until_sent(Response::new(Body::empty()), permit, None).into_body();
        assert!(body.is_end_stream(), "hyper drops an ended body without polling it");
        assert_eq!(body.size_hint().exact(), Some(0));
        drop(body);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn trailers_pass_through_after_the_data() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-check", "1".parse().unwrap());
        let inner = WithTrailers { data: Some(Bytes::from(document(CHUNK_BYTES + 1))), trailers: Some(trailers.clone()) };
        let (slots, permit) = slot();
        let mut body = hold_until_sent(Response::new(Body::new(inner)), permit, None).into_body();
        let mut received = 0;
        let mut seen = None;
        while let Some(frame) = next(&mut body).await {
            let frame = frame.expect("no error");
            match frame.into_data() {
                Ok(data) => received += data.len(),
                Err(frame) => seen = frame.into_trailers().ok(),
            }
        }
        assert_eq!(received, CHUNK_BYTES + 1);
        assert_eq!(seen, Some(trailers));
        assert_eq!(slots.available_permits(), 1);
    }

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn a_small_response_gets_the_floor() {
        assert_eq!(delivery_deadline(Duration::from_secs(30), Some(1024)), Duration::from_secs(30));
        assert_eq!(delivery_deadline(Duration::from_secs(30), Some(MIB)), Duration::from_secs(30), "8 s at the minimum rate is under the floor");
    }

    #[test]
    fn the_deadline_grows_with_the_response_at_the_minimum_rate() {
        assert_eq!(delivery_deadline(Duration::from_secs(30), Some(5 * MIB)), Duration::from_secs(40), "a 5 MiB view at 128 KiB/s");
    }

    #[test]
    fn a_large_response_gets_the_cap() {
        assert_eq!(delivery_deadline(Duration::from_secs(30), Some(19 * MIB)), DELIVERY_CAP, "152 s at the minimum rate, capped");
        assert_eq!(delivery_deadline(Duration::from_secs(30), Some(u64::MAX)), DELIVERY_CAP);
    }

    #[test]
    fn the_minimum_rate_holds_up_to_15_mib_and_a_longer_response_needs_its_length_over_the_cap() {
        let floor = Duration::from_secs(30);
        let at_the_minimum_rate = |len: u64| Duration::from_secs_f64(len as f64 / DELIVERY_MIN_RATE as f64);
        assert_eq!(DELIVERY_MIN_RATE * DELIVERY_CAP.as_secs(), 15 * MIB, "120 s at 128 KiB/s, as it states");
        assert!(delivery_deadline(floor, Some(15 * MIB)) >= at_the_minimum_rate(15 * MIB), "a reader at the minimum rate gets all of 15 MiB");
        assert!(delivery_deadline(floor, Some(16 * MIB)) < at_the_minimum_rate(16 * MIB), "and not all of a longer response");
        let longest_view = crate::limits::VIEW_GROWTH_TENTHS * crate::connectors::DEFAULT_HTTP_MAX_RESPONSE_BYTES / 10;
        assert_eq!(longest_view, 19 * MIB, "the longest /v1/invoke view at the default response cap");
        assert_eq!(longest_view / 1024 / DELIVERY_CAP.as_secs(), 162, "needs about 162 KiB a second, as it states");
    }

    #[test]
    fn a_response_of_unknown_length_gets_the_cap() {
        assert_eq!(delivery_deadline(Duration::from_secs(30), None), DELIVERY_CAP);
    }

    #[test]
    fn a_floor_set_above_the_cap_wins() {
        let floor = Duration::from_secs(300);
        assert_eq!(delivery_deadline(floor, Some(1024)), floor);
        assert_eq!(delivery_deadline(floor, Some(19 * MIB)), floor);
        assert_eq!(delivery_deadline(floor, None), floor);
    }

    #[test]
    fn guards_attached_to_a_response_accumulate() {
        let mut response = Response::new(Body::empty());
        HoldWhileSending::attach(&mut response, 1u8);
        HoldWhileSending::attach(&mut response, Arc::new(2u16));
        assert_eq!(response.extensions().get::<HoldWhileSending>().map(|hold| hold.0.len()), Some(2));
    }
}
