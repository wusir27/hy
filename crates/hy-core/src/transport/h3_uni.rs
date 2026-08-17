//! Auth-phase wrapper around `poll_accept_recv`.
//!
//! Shadowrocket may open a second HTTP/3 control uni (`0x00`) before `POST /auth`.
//! rust `h3` correctly closing on a duplicate control is left alone; this filter
//! never hands the extra stream to h3, and never `Close`s QUIC.

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{self, ConnectionErrorIncoming, RecvStream, StreamErrorIncoming, StreamId};
use std::task::{Context, Poll};

/// HTTP/3 control stream type (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;
/// QPACK encoder stream (RFC 9204).
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
/// QPACK decoder stream (RFC 9204).
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// h3 server connection used for a single `/auth` accept (hold after 233).
pub type ServerAuthH3 = h3::server::Connection<AuthUniFilter<h3_quinn::Connection>, Bytes>;

/// Connection given to `h3::server::Connection::new` during authenticate.
pub struct AuthUniFilter<C>
where
    C: quic::Connection<Bytes>,
{
    inner: C,
    saw_control: bool,
    peek: Option<(C::RecvStream, BytesMut)>,
}

impl<C> AuthUniFilter<C>
where
    C: quic::Connection<Bytes>,
{
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            saw_control: false,
            peek: None,
        }
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

impl<C> quic::OpenStreams<Bytes> for AuthUniFilter<C>
where
    C: quic::Connection<Bytes>,
    C::RecvStream: RecvStream<Buf = Bytes>,
{
    type SendStream = C::SendStream;
    type BidiStream = C::BidiStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        self.inner.poll_open_bidi(cx)
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
{
    type RecvStream = PrefixedRecv<C::RecvStream>;
    type OpenStreams = C::OpenStreams;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        self.inner.poll_accept_bidi(cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        self.inner.opener()
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
                    if let Some((mut stream, _)) = self.peek.take() {
                        abort_uni(&mut stream);
                    }
                    continue;
                }
                Ok((ty, _)) => {
                    let (mut stream, buf) = self.peek.take().expect("peek take");
                    match uni_action(ty, &mut self.saw_control) {
                        UniAction::Deliver => {
                            return Poll::Ready(Ok(PrefixedRecv {
                                inner: stream,
                                prefix: Some(buf.freeze()),
                            }));
                        }
                        UniAction::DropExtraControl => {
                            tracing::info!(
                                stream_id = %stream.recv_id(),
                                "dropping extra h3 control uni"
                            );
                            abort_uni(&mut stream);
                            continue;
                        }
                        UniAction::DropUnknown => {
                            abort_uni(&mut stream);
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
    DropExtraControl,
    DropUnknown,
}

fn uni_action(ty: u64, saw_control: &mut bool) -> UniAction {
    match ty {
        STREAM_TYPE_CONTROL if !*saw_control => {
            *saw_control = true;
            UniAction::Deliver
        }
        STREAM_TYPE_CONTROL => UniAction::DropExtraControl,
        STREAM_TYPE_QPACK_ENCODER | STREAM_TYPE_QPACK_DECODER => UniAction::Deliver,
        _ => UniAction::DropUnknown,
    }
}

fn abort_uni<R: RecvStream>(stream: &mut R) {
    stream.stop_sending(h3::error::Code::H3_STREAM_CREATION_ERROR.value());
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3::quic::{OpenStreams, SendStream};
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
        incoming: VecDeque<MockRecv>,
        stopped: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl MockConn {
        fn with_unis(payloads: &[(u64, &[u8])]) -> Self {
            let stopped = Arc::new(Mutex::new(Vec::new()));
            let incoming = payloads
                .iter()
                .map(|(id, bytes)| MockRecv {
                    id: sid(*id),
                    chunks: VecDeque::from([Bytes::copy_from_slice(bytes)]),
                    stopped: Arc::clone(&stopped),
                })
                .collect();
            Self { incoming, stopped }
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
            match self.incoming.pop_front() {
                Some(s) => Poll::Ready(Ok(s)),
                None => Poll::Pending,
            }
        }

        fn poll_accept_bidi(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
            Poll::Pending
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
        let mut filter = AuthUniFilter::new(conn);
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
        let mut filter = AuthUniFilter::new(conn);
        let mut got = drain(&mut filter);
        assert_eq!(got.len(), 3);
        assert_eq!(first_bytes(&mut got[0]), &[0x00]);
        assert_eq!(first_bytes(&mut got[1]), &[0x02]);
        assert_eq!(first_bytes(&mut got[2]), &[0x03]);
    }

    #[test]
    fn unknown_uni_reset_not_delivered() {
        let conn = MockConn::with_unis(&[(2, &[0x00]), (6, &[0x21])]);
        let stopped = Arc::clone(&conn.stopped);
        let mut filter = AuthUniFilter::new(conn);
        let got = drain(&mut filter);
        assert_eq!(got.len(), 1);
        let stopped = stopped.lock().expect("stopped");
        assert!(stopped.iter().any(|(id, _)| *id == 6), "{stopped:?}");
    }
}
