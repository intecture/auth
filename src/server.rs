// Copyright 2015-2017 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

extern crate chan;
extern crate chan_signal;
extern crate czmq;
extern crate docopt;
extern crate inauth_client;
extern crate rustc_serialize;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[cfg(test)]
extern crate tempdir;
extern crate zdaemon;
extern crate zmq;

mod api;
mod cert;
mod cert_cache;
mod config;
mod error;
mod request_meta;
mod storage;
mod zap_proxy;

use api::CertApi;
use cert_cache::CertCache;
use chan_signal::Signal;
use config::Config;
use czmq::{ZCert, ZFrame, ZMsg, ZSock, SocketType, ZSys};
use docopt::Docopt;
use error::Result;
use inauth_client::{CertType, ZapHandler};
use std::cell::RefCell;
use std::{env, fs};
use std::io::Read;
use std::rc::Rc;
use std::result::Result as StdResult;
use std::path::Path;
use std::process::exit;
use std::thread::spawn;
use storage::{PersistDisk, PersistenceAdaptor};
use zdaemon::{Api, Error as DError, Service, ZMsgExtended};

static USAGE: &'static str = "
Intecture Auth.

Usage:
  inauth [(-c <path> | --config <path>)]
  inauth (-h | --help)
  inauth --version

Options:
  -c --config <path>    Path to auth.json, e.g. \"/usr/local/etc\"
  -h --help             Show this screen.
  --version             Print this script's version.
";

#[derive(Debug, RustcDecodable)]
#[allow(non_snake_case)]
struct Args {
    flag_c: Option<String>,
    flag_config: Option<String>,
    flag_h: bool,
    flag_help: bool,
    flag_version: bool,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!(env!("CARGO_PKG_VERSION"));
        exit(0);
    } else {
        let config_path = if args.flag_c.is_some() { args.flag_c.as_ref() } else { args.flag_config.as_ref() };
        if let Err(e) = start(config_path) {
            println!("{}", e);
            exit(1);
        }
    }
}

fn start<P: AsRef<Path>>(path: Option<P>) -> Result<()> {
    let signal = chan_signal::notify(&[Signal::INT, Signal::TERM]);
    let (parent, child) = ZSys::create_pipe()?;

    let config = read_conf(path)?;

    // Create new server cert if missing
    let server_cert = match fs::metadata(&config.server_cert) {
        Ok(_) => ZCert::load(&config.server_cert)?,
        Err(_) => {
            let c = ZCert::new()?;
            c.set_meta("name", "auth");
            c.set_meta("type", CertType::Host.to_str());
            c.save_public(&format!("{}_public", &config.server_cert))?;
            c.save_secret(&config.server_cert)?;
            c
        }
    };

    let mut persistence = PersistDisk::new(&config.cert_path)?;

    let mut api_sock = ZSock::new(SocketType::ROUTER);
    api_sock.set_zap_domain("auth.intecture");
    api_sock.set_curve_server(true);
    server_cert.apply(&mut api_sock);
    api_sock.bind(&format!("tcp://*:{}", config.api_port))?;

    let _auth = ZapHandler::new(None, &server_cert, &server_cert, "127.0.0.1", config.update_port, true);

    let thread = spawn(move || {
        let mut service = Service::new(child).unwrap();

        let cert_cache = Rc::new(RefCell::new(CertCache::new(Some(persistence.dump().unwrap()))));

        let (zap_publisher, zap_subscriber) = zap_proxy::init(&server_cert, config.update_port, cert_cache.clone()).unwrap();
        service.add_endpoint(zap_publisher).unwrap();
        service.add_endpoint(zap_subscriber).unwrap();

        let api_create = Rc::new(RefCell::new(CertApi::new(persistence, cert_cache.clone()).unwrap()));
        let api_delete = api_create.clone();
        let api_list = api_create.clone();
        let api_lookup = api_create.clone();

        let mut api = Api::new(api_sock);
        api.add("cert::create", move |s: &mut ZSock, f: ZFrame, id: Option<Vec<u8>>| { let i = id.unwrap(); let r = api_create.borrow_mut().create(s, f, &i); error_handler(s, &i, r) });
        api.add("cert::delete", move |s: &mut ZSock, f: ZFrame, id: Option<Vec<u8>>| { let i = id.unwrap(); let r = api_delete.borrow_mut().delete(s, f, &i); error_handler(s, &i, r) });
        api.add("cert::list", move |s: &mut ZSock, _: ZFrame, id: Option<Vec<u8>>| { let i = id.unwrap(); let r = api_list.borrow_mut().list(s, &i); error_handler(s, &i, r) });
        api.add("cert::lookup", move |s: &mut ZSock, _: ZFrame, id: Option<Vec<u8>>| { let i = id.unwrap(); let r = api_lookup.borrow_mut().lookup(s, &i); error_handler(s, &i, r) });
        service.add_endpoint(api).unwrap();

        service.start(None).unwrap();
    });

    // Wait for interrupt from system
    signal.recv().unwrap();

    // Terminate loop
    parent.signal(1)?;
    thread.join().unwrap();

    Ok(())
}

fn error_handler(sock: &mut ZSock, router_id: &[u8], result: Result<()>) -> StdResult<(), DError> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            let derror: DError = e.into();
            let msg = ZMsg::new_err(&derror)?;
            msg.pushstr("")?;
            msg.pushbytes(router_id)?;
            msg.send(sock)?;
            Err(derror)
        }
    }
}

fn read_conf<P: AsRef<Path>>(path: Option<P>) -> Result<Config> {
    if let Some(p) = path {
        do_read_conf(p)
    }
    else if let Ok(p) = env::var("INAUTH_CONFIG_DIR") {
        do_read_conf(p)
    }
    else if let Ok(c) = do_read_conf("/usr/local/etc/intecture") {
        Ok(c)
    } else {
        do_read_conf("/etc/intecture")
    }
}

fn do_read_conf<P: AsRef<Path>>(path: P) -> Result<Config> {
    let mut path = path.as_ref().to_owned();
    path.push("auth.json");

    let mut fh = fs::File::open(&path)?;
    let mut json = String::new();
    fh.read_to_string(&mut json)?;
    Ok(serde_json::from_str(&json)?)
}

#[cfg(test)]
mod tests {
    use czmq::{ZMsg, ZSock};
    use error::Error;
    use std::{env, fs};
    use std::io::Write;
    use super::{error_handler, read_conf};
    use tempdir::TempDir;

    #[test]
    fn test_error_handler() {
        let mut client = ZSock::new_push("inproc://server_test_error_handler").unwrap();
        let mut server = ZSock::new_pull("inproc://server_test_error_handler").unwrap();
        server.set_rcvtimeo(Some(500));

        assert!(error_handler(&mut client, b"router_id", Err(Error::Forbidden)).is_err());

        let msg = ZMsg::recv(&mut server).unwrap();
        assert_eq!(msg.popstr().unwrap().unwrap(), "router_id");
        assert_eq!(msg.popstr().unwrap().unwrap(), "");
        assert_eq!(msg.popstr().unwrap().unwrap(), "Err");
        assert_eq!(msg.popstr().unwrap().unwrap(), "Access to this endpoint is forbidden");
    }

    #[test]
    fn test_read_conf() {
        let tmpdir = TempDir::new("server_test_read_conf").unwrap();
        let mut path = tmpdir.path().to_owned();

        path.push("auth.json");
        let mut fh = fs::File::create(&path).unwrap();
        fh.write_all(b"{\"server_cert\": \"/path\", \"cert_path\": \"/path\", \"api_port\": 123, \"update_port\": 123}").unwrap();
        path.pop();

        assert!(read_conf(Some(&path)).is_ok());
        env::set_var("INAUTH_CONFIG_DIR", path.to_str().unwrap());
        let none: Option<String> = None;
        assert!(read_conf(none).is_ok());
    }
}
