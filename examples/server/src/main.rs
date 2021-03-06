extern crate clap;
extern crate tokio;
extern crate tokio_rustls;

use std::sync::Arc;
use std::net::ToSocketAddrs;
use std::io::BufReader;
use std::fs::File;
use tokio_rustls::{
    ServerConfigExt,
    rustls::{
        Certificate, NoClientAuth, PrivateKey, ServerConfig,
        internal::pemfile::{ certs, rsa_private_keys }
    },
};
use tokio::prelude::{ Future, Stream };
use tokio::io::{ self, AsyncRead };
use tokio::net::TcpListener;
use clap::{ App, Arg };

fn app() -> App<'static, 'static> {
    App::new("server")
        .about("tokio-rustls server example")
        .arg(Arg::with_name("addr").value_name("ADDR").required(true))
        .arg(Arg::with_name("cert").short("c").long("cert").value_name("FILE").help("cert file.").required(true))
        .arg(Arg::with_name("key").short("k").long("key").value_name("FILE").help("key file, rsa only.").required(true))
        .arg(Arg::with_name("echo").short("e").long("echo-mode").help("echo mode."))
}

fn load_certs(path: &str) -> Vec<Certificate> {
    certs(&mut BufReader::new(File::open(path).unwrap())).unwrap()
}

fn load_keys(path: &str) -> Vec<PrivateKey> {
    rsa_private_keys(&mut BufReader::new(File::open(path).unwrap())).unwrap()
}


fn main() {
    let matches = app().get_matches();

    let addr = matches.value_of("addr").unwrap()
        .to_socket_addrs().unwrap()
        .next().unwrap();
    let cert_file = matches.value_of("cert").unwrap();
    let key_file = matches.value_of("key").unwrap();
    let flag_echo = matches.occurrences_of("echo") > 0;

    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_single_cert(load_certs(cert_file), load_keys(key_file).remove(0))
        .expect("invalid key or certificate");
    let arc_config = Arc::new(config);

    let socket = TcpListener::bind(&addr).unwrap();
    let done = socket.incoming()
        .for_each(move |stream| if flag_echo {
            let addr = stream.peer_addr().ok();
            let done = arc_config.accept_async(stream)
                .and_then(|stream| {
                    let (reader, writer) = stream.split();
                    io::copy(reader, writer)
                })
                .map(move |(n, ..)| println!("Echo: {} - {:?}", n, addr))
                .map_err(move |err| println!("Error: {:?} - {:?}", err, addr));
            tokio::spawn(done);

            Ok(())
        } else {
            let addr = stream.peer_addr().ok();
            let done = arc_config.accept_async(stream)
                .and_then(|stream| io::write_all(
                    stream,
                    &b"HTTP/1.0 200 ok\r\n\
                    Connection: close\r\n\
                    Content-length: 12\r\n\
                    \r\n\
                    Hello world!"[..]
                ))
                .and_then(|(stream, _)| io::flush(stream))
                .map(move |_| println!("Accept: {:?}", addr))
                .map_err(move |err| println!("Error: {:?} - {:?}", err, addr));
            tokio::spawn(done);

            Ok(())
        });

    tokio::run(done.map_err(drop));
}
