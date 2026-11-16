// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! Stream networking (TCP in production, simulated links in `rustegon-sim`).

use std::{io, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::BoxFuture;

/// A bidirectional byte stream.
pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Connection for T {}

/// A bound listening socket.
pub trait Listener: Send + 'static {
    /// Address actually bound (resolves port 0).
    ///
    /// # Errors
    /// I/O errors.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Waits for the next inbound connection.
    fn accept(&mut self) -> BoxFuture<'_, io::Result<(Box<dyn Connection>, SocketAddr)>>;
}

/// Network access.
pub trait Network: Send + Sync + 'static {
    /// Binds a listener.
    fn bind(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn Listener>>>;

    /// Opens a connection.
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn Connection>>>;
}

/// Production network over Tokio TCP. Requires a Tokio runtime with the I/O driver.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioNetwork;

struct TokioListener(tokio::net::TcpListener);

impl Listener for TokioListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn accept(&mut self) -> BoxFuture<'_, io::Result<(Box<dyn Connection>, SocketAddr)>> {
        Box::pin(async move {
            let (stream, peer) = self.0.accept().await?;
            // Database traffic is request/response; Nagle would delay small replies.
            stream.set_nodelay(true)?;
            Ok((Box::new(stream) as Box<dyn Connection>, peer))
        })
    }
}

// The production implementation is the one place allowed to open OS sockets (ADR-029).
#[allow(clippy::disallowed_methods)]
impl Network for TokioNetwork {
    fn bind(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn Listener>>> {
        Box::pin(async move {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            Ok(Box::new(TokioListener(listener)) as Box<dyn Listener>)
        })
    }

    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn Connection>>> {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as Box<dyn Connection>)
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn tokio_network_echo_round_trip() {
        let net = TokioNetwork;
        let mut listener = net.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(&buf).await.unwrap();
        });
        let mut client = net.connect(addr).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tokio_network_connect_refused_is_error() {
        let net = TokioNetwork;
        // Bind then drop to obtain a port with nothing listening.
        let addr = net
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(net.connect(addr).await.is_err());
    }
}
