//! Official StreamDispatcher equivalent: one `h3::quic::Connection` that owns
//! `accept_bi`, peeks the first QUIC varint, and hijacks `0x401` TCP after auth.
//!
//! Do **not** also construct `h3_quinn::Connection` on the same quinn conn.

use crate::protocol::{varint_decode, FRAME_TYPE_TCP_REQUEST};
use bytes::{Buf, Bytes};
use h3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};
use quinn::ReadError;
use std::{
    convert::TryInto,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{self, ready, Poll},
};

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Callback for a hijacked TCP proxy stream. `leftover` is bytes already read
/// *after* the consumed `0x401` varint (usually empty).
pub(crate) type TcpHijack =
    Arc<dyn Fn(quinn::SendStream, quinn::RecvStream, Vec<u8>) + Send + Sync>;

/// `h3::quic::Connection` wrapper around a raw `quinn::Connection`.
pub(crate) struct StreamDispatcher {
    conn: quinn::Connection,
    incoming_bi: BoxFut<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>,
    incoming_uni: BoxFut<Result<quinn::RecvStream, quinn::ConnectionError>>,
    opening_bi: Option<BoxFut<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>>,
    opening_uni: Option<BoxFut<Result<quinn::SendStream, quinn::ConnectionError>>>,
    peek: Option<BoxFut<Result<Peeked, PeekErr>>>,
    authenticated: Arc<AtomicBool>,
    on_tcp: TcpHijack,
}

impl StreamDispatcher {
    pub(crate) fn new(
        conn: quinn::Connection,
        authenticated: Arc<AtomicBool>,
        on_tcp: TcpHijack,
    ) -> Self {
        Self {
            incoming_bi: accept_bi_fut(conn.clone()),
            incoming_uni: accept_uni_fut(conn.clone()),
            opening_bi: None,
            opening_uni: None,
            peek: None,
            conn,
            authenticated,
            on_tcp,
        }
    }
}

fn accept_bi_fut(
    conn: quinn::Connection,
) -> BoxFut<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>> {
    Box::pin(async move { conn.accept_bi().await })
}

fn accept_uni_fut(
    conn: quinn::Connection,
) -> BoxFut<Result<quinn::RecvStream, quinn::ConnectionError>> {
    Box::pin(async move { conn.accept_uni().await })
}

fn open_bi_fut(
    conn: quinn::Connection,
) -> BoxFut<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>> {
    Box::pin(async move { conn.open_bi().await })
}

fn open_uni_fut(
    conn: quinn::Connection,
) -> BoxFut<Result<quinn::SendStream, quinn::ConnectionError>> {
    Box::pin(async move { conn.open_uni().await })
}

struct Peeked {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    frame_type: Option<u64>,
    /// Exact peeked bytes to give back to HTTP/3 (the varint encoding, plus
    /// any extra over-read — HTTP must unread everything).
    unread: Bytes,
    /// Bytes after a consumed `0x401` varint (TCP path).
    leftover: Vec<u8>,
}

enum PeekErr {
    Read(ReadError),
}

fn varint_wire_len(first: u8) -> usize {
    match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    }
}

async fn peek_bidi(send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<Peeked, PeekErr> {
    let mut prefix = Vec::new();
    loop {
        if !prefix.is_empty() {
            let n = varint_wire_len(prefix[0]);
            if prefix.len() >= n {
                let (val, consumed) = varint_decode(&prefix).expect("full varint");
                let rest = prefix[consumed..].to_vec();
                let unread = Bytes::from(prefix);
                return Ok(Peeked {
                    send,
                    recv,
                    frame_type: Some(val),
                    unread,
                    leftover: rest,
                });
            }
        }
        let want = if prefix.is_empty() {
            1
        } else {
            varint_wire_len(prefix[0]) - prefix.len()
        };
        let mut tmp = [0u8; 8];
        match recv.read(&mut tmp[..want]).await {
            Ok(Some(n)) => prefix.extend_from_slice(&tmp[..n]),
            Ok(None) => {
                return Ok(Peeked {
                    send,
                    recv,
                    frame_type: None,
                    unread: Bytes::from(prefix),
                    leftover: Vec::new(),
                });
            }
            Err(e) => return Err(PeekErr::Read(e)),
        }
    }
}

impl<B> quic::Connection<B> for StreamDispatcher
where
    B: Buf,
{
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        loop {
            if let Some(fut) = self.peek.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(res) => {
                        self.peek = None;
                        match res {
                            Ok(peeked) => {
                                let hijack = self.authenticated.load(Ordering::Acquire)
                                    && peeked.frame_type == Some(FRAME_TYPE_TCP_REQUEST);
                                if hijack {
                                    // Consume 0x401 (do not unread). Official
                                    // ReadTCPRequest starts at address length.
                                    let leftover = peeked.leftover;
                                    (self.on_tcp)(peeked.send, peeked.recv, leftover);
                                    continue;
                                }
                                return Poll::Ready(Ok(BidiStream {
                                    send: SendStream::new(peeked.send),
                                    recv: RecvStream::with_prefix(peeked.recv, peeked.unread),
                                }));
                            }
                            Err(PeekErr::Read(e)) => match convert_read_error_to_stream_error(e) {
                                StreamErrorIncoming::ConnectionErrorIncoming {
                                    connection_error,
                                } => {
                                    return Poll::Ready(Err(connection_error));
                                }
                                _ => continue,
                            },
                        }
                    }
                }
            }

            match self.incoming_bi.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok((send, recv))) => {
                    self.incoming_bi = accept_bi_fut(self.conn.clone());
                    self.peek = Some(Box::pin(peek_bidi(send, recv)));
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(convert_connection_error(e))),
            }
        }
    }

    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        match self.incoming_uni.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(recv)) => {
                self.incoming_uni = accept_uni_fut(self.conn.clone());
                Poll::Ready(Ok(RecvStream::new(recv)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(convert_connection_error(e))),
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

fn convert_connection_error(e: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match e {
        quinn::ConnectionError::ApplicationClosed(application_close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: application_close.error_code.into(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        error @ quinn::ConnectionError::VersionMismatch
        | error @ quinn::ConnectionError::Reset
        | error @ quinn::ConnectionError::LocallyClosed
        | error @ quinn::ConnectionError::CidsExhausted
        | error @ quinn::ConnectionError::TransportError(_)
        | error @ quinn::ConnectionError::ConnectionClosed(_) => {
            ConnectionErrorIncoming::Undefined(Arc::new(error))
        }
    }
}

impl<B> quic::OpenStreams<B> for StreamDispatcher
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let fut = self
            .opening_bi
            .get_or_insert_with(|| open_bi_fut(self.conn.clone()));
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok((send, recv))) => {
                self.opening_bi = None;
                Poll::Ready(Ok(BidiStream {
                    send: SendStream::new(send),
                    recv: RecvStream::new(recv),
                }))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })),
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let fut = self
            .opening_uni
            .get_or_insert_with(|| open_uni_fut(self.conn.clone()));
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(send)) => {
                self.opening_uni = None;
                Poll::Ready(Ok(SendStream::new(send)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })),
        }
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            quinn::VarInt::from_u64(code.value()).expect("error code VarInt"),
            reason,
        );
    }
}

pub(crate) struct OpenStreams {
    conn: quinn::Connection,
    opening_bi: Option<BoxFut<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>>,
    opening_uni: Option<BoxFut<Result<quinn::SendStream, quinn::ConnectionError>>>,
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

impl<B> quic::OpenStreams<B> for OpenStreams
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let fut = self
            .opening_bi
            .get_or_insert_with(|| open_bi_fut(self.conn.clone()));
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok((send, recv))) => {
                self.opening_bi = None;
                Poll::Ready(Ok(BidiStream {
                    send: SendStream::new(send),
                    recv: RecvStream::new(recv),
                }))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })),
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let fut = self
            .opening_uni
            .get_or_insert_with(|| open_uni_fut(self.conn.clone()));
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(send)) => {
                self.opening_uni = None;
                Poll::Ready(Ok(SendStream::new(send)))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })),
        }
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            quinn::VarInt::from_u64(code.value()).expect("error code VarInt"),
            reason,
        );
    }
}

pub(crate) struct BidiStream<B>
where
    B: Buf,
{
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B> quic::BidiStream<B> for BidiStream<B>
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B> quic::SendStream<B> for BidiStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B> quic::SendStreamUnframed<B> for BidiStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

/// Quinn recv stream plus an optional leftover prefix so HTTP can unread a peek.
pub(crate) struct RecvStream {
    stream: Option<quinn::RecvStream>,
    prefix: Option<Bytes>,
    read_chunk_fut: Option<
        BoxFut<(
            quinn::RecvStream,
            Result<Option<quinn::Chunk>, quinn::ReadError>,
        )>,
    >,
}

impl RecvStream {
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            stream: Some(stream),
            prefix: None,
            read_chunk_fut: None,
        }
    }

    fn with_prefix(stream: quinn::RecvStream, prefix: Bytes) -> Self {
        Self {
            stream: Some(stream),
            prefix: if prefix.is_empty() {
                None
            } else {
                Some(prefix)
            },
            read_chunk_fut: None,
        }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(prefix) = self.prefix.take() {
            if !prefix.is_empty() {
                return Poll::Ready(Ok(Some(prefix)));
            }
        }

        if self.read_chunk_fut.is_none() {
            let mut stream = self.stream.take().expect("recv stream");
            self.read_chunk_fut = Some(Box::pin(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            }));
        }

        let (stream, chunk) = ready!(self.read_chunk_fut.as_mut().unwrap().as_mut().poll(cx));
        self.read_chunk_fut = None;
        self.stream = Some(stream);
        Poll::Ready(Ok(chunk
            .map_err(convert_read_error_to_stream_error)?
            .map(|c| c.bytes)))
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.stream
            .as_mut()
            .unwrap()
            .stop(quinn::VarInt::from_u64(error_code).expect("invalid error_code"))
            .ok();
    }

    fn recv_id(&self) -> StreamId {
        let num: u64 = self.stream.as_ref().unwrap().id().into();
        num.try_into().expect("invalid stream id")
    }
}

fn convert_read_error_to_stream_error(error: ReadError) -> StreamErrorIncoming {
    match error {
        ReadError::Reset(var_int) => StreamErrorIncoming::StreamTerminated {
            error_code: var_int.into_inner(),
        },
        ReadError::ConnectionLost(connection_error) => {
            StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(connection_error),
            }
        }
        error @ ReadError::ClosedStream => StreamErrorIncoming::Unknown(Box::new(error)),
        ReadError::IllegalOrderedRead => panic!("StreamDispatcher only performs ordered reads"),
        error @ ReadError::ZeroRttRejected => StreamErrorIncoming::Unknown(Box::new(error)),
    }
}

fn convert_write_error_to_stream_error(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(var_int) => StreamErrorIncoming::StreamTerminated {
            error_code: var_int.into_inner(),
        },
        quinn::WriteError::ConnectionLost(connection_error) => {
            StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(connection_error),
            }
        }
        error @ quinn::WriteError::ClosedStream | error @ quinn::WriteError::ZeroRttRejected => {
            StreamErrorIncoming::Unknown(Box::new(error))
        }
    }
}

pub(crate) struct SendStream<B: Buf> {
    stream: quinn::SendStream,
    writing: Option<WriteBuf<B>>,
}

impl<B> SendStream<B>
where
    B: Buf,
{
    fn new(stream: quinn::SendStream) -> SendStream<B> {
        Self {
            stream,
            writing: None,
        }
    }
}

impl<B> quic::SendStream<B> for SendStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(ref mut data) = self.writing {
            while data.has_remaining() {
                let stream = Pin::new(&mut self.stream);
                let written = ready!(stream.poll_write(cx, data.chunk()))
                    .map_err(convert_write_error_to_stream_error)?;
                data.advance(written);
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn poll_finish(
        &mut self,
        _cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))),
        )
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(quinn::VarInt::from_u64(reset_code).unwrap_or(quinn::VarInt::MAX));
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "internal error in the http stack".to_string(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn send_id(&self) -> StreamId {
        let num: u64 = self.stream.id().into();
        num.try_into().expect("invalid stream id")
    }
}

impl<B> quic::SendStreamUnframed<B> for SendStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        if self.writing.is_some() {
            panic!("poll_send called while send stream is not ready")
        }

        let s = Pin::new(&mut self.stream);
        match ready!(s.poll_write(cx, buf.chunk())) {
            Ok(written) => {
                buf.advance(written);
                Poll::Ready(Ok(written))
            }
            Err(err) => Poll::Ready(Err(convert_write_error_to_stream_error(err))),
        }
    }
}
