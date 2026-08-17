//! Wrapper around `poll_accept_recv` and `poll_accept_bidi`.
//!
//! Shadowrocket may open extra HTTP/3 unis before `POST /auth`: a second control
//! (`0x00`), QPACK encoder (`0x02`), or QPACK decoder (`0x03`). rust `h3`
//! correctly closing on a duplicate is left alone; this filter never hands the
//! extra stream to h3, and never `Close`s QUIC.
//!
//! Before the first 233, extra / unknown unis are reset (`stop_sending`) so
//! authenticate does not see `got two * streams`. After 233 they are taken out
//! of `poll_accept_recv` and **held** until the connection dies — Quinn
//! `RecvStream` Drop is STOP_SENDING, which the client treats as failure and
//! `Close(0x0)`.
//!
//! Inbound bidis are peeked: `0x401` (Hysteria TCP) is queued for `handle_tcp`
//! (outbound only after 233) and is never given to h3. HTTP bytes are put back.
//! After 233 the same wrapper is still polled (`h3.accept`); do not raw-accept.

use crate::protocol::FRAME_TYPE_TCP_REQUEST;
use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{
    self, ConnectionErrorIncoming, RecvStream, SendStream, SendStreamUnframed, StreamErrorIncoming,
    StreamId,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

/// HTTP/3 control stream type (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;
/// QPACK encoder stream (RFC 9204).
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
/// QPACK decoder stream (RFC 9204).
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;
/// HTTP/3 HEADERS frame (RFC 9114). Request streams start with this.
/// A DATA (0x00) first frame makes rust `h3` close QUIC (`H3_FRAME_UNEXPECTED`).
const H3_FRAME_HEADERS: u64 = 0x01;

/// A `0x401` bidi hijacked during authenticate. Do not dial until 233.
pub type QueuedTcpBidi = (h3_quinn::BidiStream<Bytes>, Bytes);

/// h3 server connection used for `/auth` and kept as the only bidi owner after 233.
pub type ServerAuthH3 = h3::server::Connection<AuthUniFilter<h3_quinn::Connection>, Bytes>;

/// Connection given to `h3::server::Connection::new` during authenticate.
pub struct AuthUniFilter<C>
where
    C: quic::Connection<Bytes>,
{
    inner: C,
    saw_control: bool,
    saw_qpack_encoder: bool,
    saw_qpack_decoder: bool,
    peek: Option<(C::RecvStream, BytesMut)>,
    bidi_peek: Option<(C::BidiStream, BytesMut)>,
    tcp_tx: mpsc::UnboundedSender<(C::BidiStream, Bytes)>,
    /// Set immediately after the first 233. Extra unis are held, not reset.
    authed: Arc<AtomicBool>,
    /// Extra / unknown unis accepted after 233. Must not Drop until QUIC dies.
    held_unis: Vec<C::RecvStream>,
}

impl<C> AuthUniFilter<C>
where
    C: quic::Connection<Bytes>,
{
    pub fn new(inner: C) -> (Self, mpsc::UnboundedReceiver<(C::BidiStream, Bytes)>) {
        let (tcp_tx, tcp_rx) = mpsc::unbounded_channel();
        (Self::with_tcp_tx(inner, tcp_tx), tcp_rx)
    }

    pub fn with_tcp_tx(inner: C, tcp_tx: mpsc::UnboundedSender<(C::BidiStream, Bytes)>) -> Self {
        Self::with_tcp_tx_authed(inner, tcp_tx, Arc::new(AtomicBool::new(false)))
    }

    pub fn with_tcp_tx_authed(
        inner: C,
        tcp_tx: mpsc::UnboundedSender<(C::BidiStream, Bytes)>,
        authed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            saw_control: false,
            saw_qpack_encoder: false,
            saw_qpack_decoder: false,
            peek: None,
            bidi_peek: None,
            tcp_tx,
            authed,
            held_unis: Vec::new(),
        }
    }

    /// First 233 succeeded. Extra unis from this point must be held, not reset.
    pub fn mark_authenticated(&self) {
        self.authed.store(true, Ordering::Release);
    }
}

/// Recv stream that prepends bytes already read while peeking the type varint.
pub struct PrefixedRecv<R> {
    inner: R,
    prefix: Option<Bytes>,
}

impl<R> RecvStream for PrefixedRecv<R>
where
    R: RecvStream<Buf = Bytes>,
{
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(prefix) = self.prefix.take() {
            if !prefix.is_empty() {
                return Poll::Ready(Ok(Some(prefix)));
            }
        }
        self.inner.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

/// Bidi that prepends bytes already read while peeking the first varint.
pub struct PrefixedBidi<S> {
    inner: S,
    prefix: Option<Bytes>,
}

fn restore_bidi<S>(inner: S, prefix: Bytes) -> PrefixedBidi<S> {
    PrefixedBidi {
        inner,
        prefix: if prefix.is_empty() { None } else { Some(prefix) },
    }
}

impl<S> RecvStream for PrefixedBidi<S>
where
    S: RecvStream<Buf = Bytes>,
{
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(prefix) = self.prefix.take() {
            if !prefix.is_empty() {
                return Poll::Ready(Ok(Some(prefix)));
            }
        }
        self.inner.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code);
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

impl<S, B> SendStream<B> for PrefixedBidi<S>
where
    S: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }

    fn send_data<T: Into<h3::quic::WriteBuf<B>>>(
        &mut self,
        data: T,
    ) -> Result<(), StreamErrorIncoming> {
        self.inner.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.inner.reset(reset_code);
    }

    fn send_id(&self) -> StreamId {
        self.inner.send_id()
    }
}

impl<S, B> SendStreamUnframed<B> for PrefixedBidi<S>
where
    S: SendStreamUnframed<B>,
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.inner.poll_send(cx, buf)
    }
}

impl<S, B> quic::BidiStream<B> for PrefixedBidi<S>
where
    S: quic::BidiStream<B> + RecvStream<Buf = Bytes>,
    S::RecvStream: RecvStream<Buf = Bytes>,
    B: Buf,
{
    type SendStream = S::SendStream;
    type RecvStream = PrefixedRecv<S::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();
        (
            send,
            PrefixedRecv {
                inner: recv,
                prefix: self.prefix,
            },
        )
    }
}

/// Opener whose bidis match `AuthUniFilter` (prefix wrapper, empty prefix).
pub struct AuthOpener<O> {
    inner: O,
}

impl<O> Clone for AuthOpener<O>
where
    O: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<O> quic::OpenStreams<Bytes> for AuthOpener<O>
where
    O: quic::OpenStreams<Bytes>,
    O::BidiStream: RecvStream<Buf = Bytes>,
{
    type SendStream = O::SendStream;
    type BidiStream = PrefixedBidi<O::BidiStream>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.inner.poll_open_bidi(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(s)) => Poll::Ready(Ok(restore_bidi(s, Bytes::new()))),
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

impl<C> quic::OpenStreams<Bytes> for AuthUniFilter<C>
where
    C: quic::Connection<Bytes>,
    C::RecvStream: RecvStream<Buf = Bytes>,
    C::BidiStream: RecvStream<Buf = Bytes>,
{
    type SendStream = C::SendStream;
    type BidiStream = PrefixedBidi<C::BidiStream>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.inner.poll_open_bidi(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(s)) => Poll::Ready(Ok(restore_bidi(s, Bytes::new()))),
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

impl<C> quic::Connection<Bytes> for AuthUniFilter<C>
where
    C: quic::Connection<Bytes>,
    C::RecvStream: RecvStream<Buf = Bytes>,
    C::BidiStream: RecvStream<Buf = Bytes>,
{
    type RecvStream = PrefixedRecv<C::RecvStream>;
    type OpenStreams = AuthOpener<C::OpenStreams>;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        loop {
            if self.bidi_peek.is_none() {
                match self.inner.poll_accept_bidi(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(stream)) => {
                        self.bidi_peek = Some((stream, BytesMut::new()));
                    }
                }
            }

            let chunk = {
                let (stream, _) = self.bidi_peek.as_mut().expect("bidi peek stream");
                match RecvStream::poll_data(stream, cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error,
                    })) => {
                        self.bidi_peek = None;
                        return Poll::Ready(Err(connection_error));
                    }
                    Poll::Ready(Err(_)) => {
                        self.bidi_peek = None;
                        continue;
                    }
                    Poll::Ready(Ok(None)) => {
                        self.bidi_peek = None;
                        continue;
                    }
                    Poll::Ready(Ok(Some(data))) => data,
                }
            };

            let (_, buf) = self.bidi_peek.as_mut().expect("bidi peek buf");
            buf.extend_from_slice(chunk.chunk());

            match crate::protocol::varint_decode(buf) {
                Err(_) if buf.len() < 8 => continue,
                Err(_) => {
                    let (stream, buf) = self.bidi_peek.take().expect("bidi peek take");
                    return Poll::Ready(Ok(restore_bidi(stream, buf.freeze())));
                }
                Ok((ty, _)) => {
                    let (stream, buf) = self.bidi_peek.take().expect("bidi peek take");
                    if ty == FRAME_TYPE_TCP_REQUEST {
                        tracing::info!(
                            stream_id = %RecvStream::recv_id(&stream),
                            "queued 0x401"
                        );
                        let _ = self.tcp_tx.send((stream, buf.freeze()));
                        continue;
                    }
                    if ty != H3_FRAME_HEADERS {
                        tracing::info!(
                            stream_id = %RecvStream::recv_id(&stream),
                            frame = ty,
                            "dropping non-http bidi"
                        );
                        drop(stream);
                        continue;
                    }
                    return Poll::Ready(Ok(restore_bidi(stream, buf.freeze())));
                }
            }
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        AuthOpener {
            inner: self.inner.opener(),
        }
    }

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        loop {
            if self.peek.is_none() {
                match self.inner.poll_accept_recv(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(stream)) => {
                        self.peek = Some((stream, BytesMut::new()));
                    }
                }
            }

            let chunk = {
                let (stream, _) = self.peek.as_mut().expect("peek stream");
                match stream.poll_data(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                        connection_error,
                    })) => {
                        self.peek = None;
                        return Poll::Ready(Err(connection_error));
                    }
                    Poll::Ready(Err(_)) => {
                        self.peek = None;
                        continue;
                    }
                    Poll::Ready(Ok(None)) => {
                        self.peek = None;
                        continue;
                    }
                    Poll::Ready(Ok(Some(data))) => data,
                }
            };

            let (_, buf) = self.peek.as_mut().expect("peek buf");
            buf.extend_from_slice(chunk.chunk());

            match crate::protocol::varint_decode(buf) {
                Err(_) if buf.len() < 8 => continue,
                Err(_) => {
                    if let Some((stream, _)) = self.peek.take() {
                        drop_or_hold_uni(
                            &self.authed,
                            &mut self.held_unis,
                            stream,
                            None,
                            false,
                        );
                    }
                    continue;
                }
                Ok((ty, _)) => {
                    let (stream, buf) = self.peek.take().expect("peek take");
                    match uni_action(
                        ty,
                        &mut self.saw_control,
                        &mut self.saw_qpack_encoder,
                        &mut self.saw_qpack_decoder,
                    ) {
                        UniAction::Deliver => {
                            return Poll::Ready(Ok(PrefixedRecv {
                                inner: stream,
                                prefix: Some(buf.freeze()),
                            }));
                        }
                        UniAction::DropExtra => {
                            drop_or_hold_uni(
                                &self.authed,
                                &mut self.held_unis,
                                stream,
                                Some(ty),
                                true,
                            );
                            continue;
                        }
                        UniAction::DropUnknown => {
                            drop_or_hold_uni(
                                &self.authed,
                                &mut self.held_unis,
                                stream,
                                Some(ty),
                                false,
                            );
                            continue;
                        }
                    }
                }
            }
        }
    }
}

enum UniAction {
    Deliver,
    DropExtra,
    DropUnknown,
}

fn uni_action(
    ty: u64,
    saw_control: &mut bool,
    saw_qpack_encoder: &mut bool,
    saw_qpack_decoder: &mut bool,
) -> UniAction {
    match ty {
        STREAM_TYPE_CONTROL => first_or_extra(saw_control),
        STREAM_TYPE_QPACK_ENCODER => first_or_extra(saw_qpack_encoder),
        STREAM_TYPE_QPACK_DECODER => first_or_extra(saw_qpack_decoder),
        _ => UniAction::DropUnknown,
    }
}

fn first_or_extra(saw: &mut bool) -> UniAction {
    if !*saw {
        *saw = true;
        UniAction::Deliver
    } else {
        UniAction::DropExtra
    }
}

fn drop_or_hold_uni<R: RecvStream>(
    authed: &AtomicBool,
    held: &mut Vec<R>,
    mut stream: R,
    ty: Option<u64>,
    extra: bool,
) {
    if authed.load(Ordering::Acquire) {
        match ty {
            Some(ty) => tracing::info!(
                stream_type = ty,
                stream_id = %stream.recv_id(),
                "holding extra h3 uni"
            ),
            None => tracing::info!(
                stream_id = %stream.recv_id(),
                "holding extra h3 uni"
            ),
        }
        held.push(stream);
        return;
    }
    if extra {
        if let Some(ty) = ty {
            tracing::info!(
                stream_type = ty,
                stream_id = %stream.recv_id(),
                "dropping extra h3 uni"
            );
        }
    }
    abort_uni(&mut stream);
}

fn abort_uni<R: RecvStream>(stream: &mut R) {
    stream.stop_sending(h3::error::Code::H3_STREAM_CREATION_ERROR.value());
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3::quic::{OpenStreams, RecvStream, SendStream};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    fn sid(id: u64) -> StreamId {
        StreamId::try_from(id).expect("stream id")
    }

    struct MockRecv {
        id: StreamId,
        chunks: VecDeque<Bytes>,
        stopped: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl RecvStream for MockRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            Poll::Ready(Ok(self.chunks.pop_front()))
        }

        fn stop_sending(&mut self, error_code: u64) {
            self.stopped
                .lock()
                .expect("stopped lock")
                .push((self.id.into_inner(), error_code));
        }

        fn recv_id(&self) -> StreamId {
            self.id
        }
    }

    /// Quinn `RecvStream` Drop sends STOP_SENDING. Record that so after-auth
    /// holds are distinguishable from silent `drop(stream)`.
    impl Drop for MockRecv {
        fn drop(&mut self) {
            if let Ok(mut stopped) = self.stopped.lock() {
                let id = self.id.into_inner();
                if !stopped.iter().any(|(i, _)| *i == id) {
                    stopped.push((id, 0));
                }
            }
        }
    }

    fn mock_recv(id: u64, bytes: &[u8], stopped: &Arc<Mutex<Vec<(u64, u64)>>>) -> MockRecv {
        MockRecv {
            id: sid(id),
            chunks: VecDeque::from([Bytes::copy_from_slice(bytes)]),
            stopped: Arc::clone(stopped),
        }
    }

    struct DummySend;

    impl SendStream<Bytes> for DummySend {
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), StreamErrorIncoming>> {
            Poll::Pending
        }

        fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(
            &mut self,
            _data: T,
        ) -> Result<(), StreamErrorIncoming> {
            Ok(())
        }

        fn poll_finish(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), StreamErrorIncoming>> {
            Poll::Pending
        }

        fn reset(&mut self, _reset_code: u64) {}

        fn send_id(&self) -> StreamId {
            sid(3)
        }
    }

    struct DummyBidi {
        send: DummySend,
        recv: MockRecv,
    }

    impl RecvStream for DummyBidi {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.recv.poll_data(cx)
        }

        fn stop_sending(&mut self, error_code: u64) {
            self.recv.stop_sending(error_code);
        }

        fn recv_id(&self) -> StreamId {
            self.recv.recv_id()
        }
    }

    impl SendStream<Bytes> for DummyBidi {
        fn poll_ready(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), StreamErrorIncoming>> {
            self.send.poll_ready(cx)
        }

        fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(
            &mut self,
            data: T,
        ) -> Result<(), StreamErrorIncoming> {
            self.send.send_data(data)
        }

        fn poll_finish(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), StreamErrorIncoming>> {
            self.send.poll_finish(cx)
        }

        fn reset(&mut self, reset_code: u64) {
            self.send.reset(reset_code);
        }

        fn send_id(&self) -> StreamId {
            self.send.send_id()
        }
    }

    impl quic::BidiStream<Bytes> for DummyBidi {
        type SendStream = DummySend;
        type RecvStream = MockRecv;

        fn split(self) -> (Self::SendStream, Self::RecvStream) {
            (self.send, self.recv)
        }
    }

    struct MockOpener;

    impl OpenStreams<Bytes> for MockOpener {
        type SendStream = DummySend;
        type BidiStream = DummyBidi;

        fn poll_open_bidi(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
            Poll::Pending
        }

        fn poll_open_send(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
            Poll::Pending
        }

        fn close(&mut self, _code: h3::error::Code, _reason: &[u8]) {}
    }

    struct MockConn {
        incoming: Arc<Mutex<VecDeque<MockRecv>>>,
        incoming_bidi: Arc<Mutex<VecDeque<DummyBidi>>>,
        stopped: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl MockConn {
        fn with_unis(payloads: &[(u64, &[u8])]) -> Self {
            Self::with_streams(payloads, &[])
        }

        fn with_bidi(payloads: &[(u64, &[u8])]) -> Self {
            Self::with_streams(&[], payloads)
        }

        fn with_streams(unis: &[(u64, &[u8])], bidis: &[(u64, &[u8])]) -> Self {
            let stopped = Arc::new(Mutex::new(Vec::new()));
            let incoming = unis
                .iter()
                .map(|(id, bytes)| mock_recv(*id, bytes, &stopped))
                .collect();
            let incoming_bidi = bidis
                .iter()
                .map(|(id, bytes)| DummyBidi {
                    send: DummySend,
                    recv: mock_recv(*id, bytes, &stopped),
                })
                .collect();
            Self {
                incoming: Arc::new(Mutex::new(incoming)),
                incoming_bidi: Arc::new(Mutex::new(incoming_bidi)),
                stopped,
            }
        }
    }

    impl OpenStreams<Bytes> for MockConn {
        type SendStream = DummySend;
        type BidiStream = DummyBidi;

        fn poll_open_bidi(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
            Poll::Pending
        }

        fn poll_open_send(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
            Poll::Pending
        }

        fn close(&mut self, _code: h3::error::Code, _reason: &[u8]) {}
    }

    impl quic::Connection<Bytes> for MockConn {
        type RecvStream = MockRecv;
        type OpenStreams = MockOpener;

        fn poll_accept_recv(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
            match self.incoming.lock().expect("incoming").pop_front() {
                Some(s) => Poll::Ready(Ok(s)),
                None => Poll::Pending,
            }
        }

        fn poll_accept_bidi(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
            match self.incoming_bidi.lock().expect("incoming_bidi").pop_front() {
                Some(s) => Poll::Ready(Ok(s)),
                None => Poll::Pending,
            }
        }

        fn opener(&self) -> Self::OpenStreams {
            MockOpener
        }
    }

    fn drain(filter: &mut AuthUniFilter<MockConn>) -> Vec<PrefixedRecv<MockRecv>> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut out = Vec::new();
        loop {
            match quic::Connection::poll_accept_recv(filter, &mut cx) {
                Poll::Ready(Ok(s)) => out.push(s),
                Poll::Ready(Err(e)) => panic!("poll_accept_recv error: {e:?}"),
                Poll::Pending => break,
            }
        }
        out
    }

    fn first_bytes(stream: &mut PrefixedRecv<MockRecv>) -> Vec<u8> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match stream.poll_data(&mut cx) {
            Poll::Ready(Ok(Some(b))) => b.to_vec(),
            other => panic!("expected prefix bytes, got {other:?}"),
        }
    }

    #[test]
    fn extra_control_uni_is_hidden_first_control_bytes_restored() {
        let conn = MockConn::with_unis(&[
            (2, &[0x00, 0x04, 0x00]),
            (6, &[0x00, 0x04, 0x00]),
        ]);
        let stopped = Arc::clone(&conn.stopped);
        let (mut filter, _tcp) = AuthUniFilter::new(conn);
        let mut got = drain(&mut filter);
        assert_eq!(got.len(), 1, "second 0x00 must not be returned to h3");
        assert_eq!(first_bytes(&mut got[0]), &[0x00, 0x04, 0x00]);
        let stopped = stopped.lock().expect("stopped");
        assert!(
            stopped.iter().any(|(id, _)| *id == 6),
            "extra control uni must be reset, got {stopped:?}"
        );
    }

    #[test]
    fn qpack_unis_reach_h3() {
        let conn = MockConn::with_unis(&[
            (2, &[0x00]),
            (6, &[0x02]),
            (10, &[0x03]),
        ]);
        let (mut filter, _tcp) = AuthUniFilter::new(conn);
        let mut got = drain(&mut filter);
        assert_eq!(got.len(), 3);
        assert_eq!(first_bytes(&mut got[0]), &[0x00]);
        assert_eq!(first_bytes(&mut got[1]), &[0x02]);
        assert_eq!(first_bytes(&mut got[2]), &[0x03]);
    }

    #[test]
    fn extra_qpack_encoder_uni_is_hidden() {
        let conn = MockConn::with_unis(&[
            (2, &[0x00]),
            (6, &[0x02, 0xaa]),
            (10, &[0x02, 0xbb]),
            (14, &[0x03]),
        ]);
        let stopped = Arc::clone(&conn.stopped);
        let (mut filter, _tcp) = AuthUniFilter::new(conn);
        let mut got = drain(&mut filter);
        assert_eq!(got.len(), 3, "second 0x02 must not be returned to h3");
        assert_eq!(first_bytes(&mut got[0]), &[0x00]);
        assert_eq!(first_bytes(&mut got[1]), &[0x02, 0xaa]);
        assert_eq!(first_bytes(&mut got[2]), &[0x03]);
        let stopped = stopped.lock().expect("stopped");
        assert!(
            stopped.iter().any(|(id, _)| *id == 10),
            "extra encoder uni must be reset, got {stopped:?}"
        );
        assert!(
            !stopped.iter().any(|(id, _)| *id == 6),
            "first encoder must reach h3, got {stopped:?}"
        );
    }

    #[test]
    fn extra_qpack_decoder_uni_is_hidden() {
        let conn = MockConn::with_unis(&[
            (2, &[0x00]),
            (6, &[0x02]),
            (10, &[0x03, 0xaa]),
            (14, &[0x03, 0xbb]),
        ]);
        let stopped = Arc::clone(&conn.stopped);
        let (mut filter, _tcp) = AuthUniFilter::new(conn);
        let mut got = drain(&mut filter);
        assert_eq!(got.len(), 3, "second 0x03 must not be returned to h3");
        assert_eq!(first_bytes(&mut got[0]), &[0x00]);
        assert_eq!(first_bytes(&mut got[1]), &[0x02]);
        assert_eq!(first_bytes(&mut got[2]), &[0x03, 0xaa]);
        let stopped = stopped.lock().expect("stopped");
        assert!(
            stopped.iter().any(|(id, _)| *id == 14),
            "extra decoder uni must be reset, got {stopped:?}"
        );
        assert!(
            !stopped.iter().any(|(id, _)| *id == 10),
            "first decoder must reach h3, got {stopped:?}"
        );
    }

    #[test]
    fn unknown_uni_reset_not_delivered() {
        let conn = MockConn::with_unis(&[(2, &[0x00]), (6, &[0x21])]);
        let stopped = Arc::clone(&conn.stopped);
        let (mut filter, _tcp) = AuthUniFilter::new(conn);
        let got = drain(&mut filter);
        assert_eq!(got.len(), 1);
        let stopped = stopped.lock().expect("stopped");
        assert!(stopped.iter().any(|(id, _)| *id == 6), "{stopped:?}");
    }

    #[test]
    fn extra_unis_after_auth_are_held_not_stopped() {
        let authed = Arc::new(AtomicBool::new(false));
        let conn = MockConn::with_unis(&[(2, &[0x00]), (6, &[0x02]), (10, &[0x03])]);
        let stopped = Arc::clone(&conn.stopped);
        let incoming = Arc::clone(&conn.incoming);
        let (tcp_tx, _tcp) = mpsc::unbounded_channel();
        let mut filter = AuthUniFilter::with_tcp_tx_authed(conn, tcp_tx, Arc::clone(&authed));
        let mut got = drain(&mut filter);
        assert_eq!(got.len(), 3);
        assert_eq!(first_bytes(&mut got[0]), &[0x00]);
        assert_eq!(first_bytes(&mut got[1]), &[0x02]);
        assert_eq!(first_bytes(&mut got[2]), &[0x03]);

        authed.store(true, Ordering::Release);
        incoming.lock().expect("incoming").extend([
            mock_recv(14, &[0x00], &stopped),
            mock_recv(18, &[0x02], &stopped),
            mock_recv(22, &[0x03], &stopped),
            mock_recv(26, &[0x21], &stopped),
        ]);
        let more = drain(&mut filter);
        assert!(
            more.is_empty(),
            "extra unis after auth must not be returned to h3"
        );
        let stopped_now = stopped.lock().expect("stopped");
        for id in [14u64, 18, 22, 26] {
            assert!(
                !stopped_now.iter().any(|(i, _)| *i == id),
                "after auth extra uni {id} must not be stopped, got {stopped_now:?}"
            );
        }
        drop(stopped_now);
        assert_eq!(
            filter.held_unis.len(),
            4,
            "extra 0x00/0x02/0x03 and unknown must be held"
        );
    }

    fn drain_bidi(filter: &mut AuthUniFilter<MockConn>) -> Vec<PrefixedBidi<DummyBidi>> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut out = Vec::new();
        loop {
            match quic::Connection::poll_accept_bidi(filter, &mut cx) {
                Poll::Ready(Ok(s)) => out.push(s),
                Poll::Ready(Err(e)) => panic!("poll_accept_bidi error: {e:?}"),
                Poll::Pending => break,
            }
        }
        out
    }

    fn first_bytes_bidi(stream: &mut PrefixedBidi<DummyBidi>) -> Vec<u8> {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match RecvStream::poll_data(stream, &mut cx) {
            Poll::Ready(Ok(Some(b))) => b.to_vec(),
            other => panic!("expected prefix bytes, got {other:?}"),
        }
    }

    #[test]
    fn tcp_request_bidi_is_queued_http_bytes_restored() {
        let conn = MockConn::with_bidi(&[
            (0, &[0x44, 0x01, 0x0e]),
            (4, &[0x01, 0x40]),
        ]);
        let (mut filter, mut tcp_rx) = AuthUniFilter::new(conn);
        let mut got = drain_bidi(&mut filter);
        assert_eq!(got.len(), 1, "0x401 must not be returned to h3");
        assert_eq!(first_bytes_bidi(&mut got[0]), &[0x01, 0x40]);
        let (queued, prefix) = tcp_rx.try_recv().expect("0x401 queued");
        assert_eq!(&prefix[..], &[0x44, 0x01, 0x0e]);
        assert_eq!(queued.recv_id().into_inner(), 0);
        assert!(tcp_rx.try_recv().is_err());
    }

    #[test]
    fn first_bidi_tcp_request_is_queued_until_http_arrives() {
        let conn = MockConn::with_bidi(&[(0, &[0x44, 0x01])]);
        let (mut filter, mut tcp_rx) = AuthUniFilter::new(conn);
        let got = drain_bidi(&mut filter);
        assert!(got.is_empty(), "0x401 must not enter resolve_request");
        let (_, prefix) = tcp_rx.try_recv().expect("queued before /auth");
        assert_eq!(&prefix[..], &[0x44, 0x01]);
    }

    #[test]
    fn non_http_non_tcp_bidi_is_not_given_to_h3() {
        let conn = MockConn::with_bidi(&[(0, &[0x00]), (4, &[0x01, 0x40])]);
        let (mut filter, mut tcp_rx) = AuthUniFilter::new(conn);
        let mut got = drain_bidi(&mut filter);
        assert_eq!(got.len(), 1, "0x00 bidi must not be returned to h3");
        assert_eq!(first_bytes_bidi(&mut got[0]), &[0x01, 0x40]);
        assert!(tcp_rx.try_recv().is_err());
    }

    #[test]
    fn tcp_request_after_auth_still_queued_while_holding_extras() {
        let conn = MockConn::with_unis(&[(2, &[0x00]), (6, &[0x02]), (10, &[0x03])]);
        let stopped = Arc::clone(&conn.stopped);
        let incoming = Arc::clone(&conn.incoming);
        let incoming_bidi = Arc::clone(&conn.incoming_bidi);
        let (mut filter, mut tcp_rx) = AuthUniFilter::new(conn);
        let got = drain(&mut filter);
        assert_eq!(got.len(), 3);
        filter.mark_authenticated();
        incoming.lock().expect("incoming").extend([
            mock_recv(14, &[0x00], &stopped),
            mock_recv(18, &[0x02], &stopped),
            mock_recv(22, &[0x03], &stopped),
        ]);
        incoming_bidi.lock().expect("incoming_bidi").push_back(DummyBidi {
            send: DummySend,
            recv: mock_recv(4, &[0x44, 0x01], &stopped),
        });
        let more_uni = drain(&mut filter);
        assert!(more_uni.is_empty());
        let got_bidi = drain_bidi(&mut filter);
        assert!(got_bidi.is_empty(), "0x401 must not enter h3");
        let (_, prefix) = tcp_rx.try_recv().expect("0x401 after 233");
        assert_eq!(&prefix[..], &[0x44, 0x01]);
        let stopped_now = stopped.lock().expect("stopped");
        for id in [14u64, 18, 22] {
            assert!(
                !stopped_now.iter().any(|(i, _)| *i == id),
                "extra uni {id} must not be stopped, got {stopped_now:?}"
            );
        }
        drop(stopped_now);
        assert_eq!(filter.held_unis.len(), 3);
    }
}
