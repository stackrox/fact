use std::{convert::Infallible, net::SocketAddr};

use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, task::JoinHandle};

pub fn start() -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], 9000));
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_| async move {
                            Ok::<Response<Full<Bytes>>, Infallible>(Response::new(Full::new(
                                Bytes::from(""),
                            )))
                        }),
                    )
                    .await
                {
                    eprintln!("Error serving connection: {err:?}");
                }
            });
        }
    })
}
