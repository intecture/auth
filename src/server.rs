// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

extern crate chan;
extern crate chan_signal;
extern crate czmq;
extern crate inauth_client;
extern crate rustc_serialize;
#[cfg(test)]
extern crate tempdir;
extern crate zdaemon;

mod api;
mod cert;
mod cert_cache;
mod config;
#[allow(dead_code)]
mod error;
mod request_meta;
mod storage;
mod zap_proxy;

use api::CertApi;
use cert_cache::CertCache;
use chan_signal::Signal;
use config::Config;
use czmq::{ZCert, ZFrame, ZMsg, ZSock, SocketType, ZSys};
use error::Result;
use inauth_client::{CertType, ZapHandler};
use std::cell::RefCell;
use std::fs::metadata;
use std::rc::Rc;
use std::result::Result as StdResult;
use std::process::exit;
use std::thread::spawn;
use storage::{PersistDisk, PersistenceAdaptor};
use zdaemon::{Api, ConfigFile, Error as DError, Service, ZMsgExtended};

fn main() {
    if let Err(e) = start() {
        println!("{}", e);
        exit(1);
    }
}

fn start() -> Result<()> {
    let signal = chan_signal::notify(&[Signal::INT, Signal::TERM]);
    let (parent, child) = ZSys::create_pipe()?;

    let config = Config::search("intecture/auth.json", None)?;

    // Create new server cert if missing
    let server_cert = match metadata(&config.server_cert) {
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
            let msg = ZMsg::new_err(&derror, Some(router_id))?;
            msg.send(sock)?;
            Err(derror)
        }
    }
}

#[cfg(test)]
mod tests {
    use czmq::{ZMsg, ZSock};
    use error::Error;
    use super::error_handler;

    #[test]
    fn test_error_handler() {
        let mut client = ZSock::new_push("inproc://server_test_error_handler").unwrap();
        let mut server = ZSock::new_pull("inproc://server_test_error_handler").unwrap();
        server.set_rcvtimeo(Some(500));

        assert!(error_handler(&mut client, b"router_id", Err(Error::Forbidden)).is_err());

        let msg = ZMsg::recv(&mut server).unwrap();
        assert_eq!(msg.popstr().unwrap().unwrap(), "router_id");
        assert_eq!(msg.popstr().unwrap().unwrap(), "Err");
        assert_eq!(msg.popstr().unwrap().unwrap(), "Access to this endpoint is forbidden");
    }
}
