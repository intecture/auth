// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

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
use config::Config;
use czmq::{ZCert, ZFrame, ZMsg, ZSock, ZSockType};
use error::{Error, Result};
use inauth_client::{CertType, ZapHandler};
use std::cell::RefCell;
use std::fmt::{Debug, Display};
use std::fs::metadata;
use std::rc::Rc;
use std::result::Result as StdResult;
use std::process::exit;
use storage::{PersistDisk, PersistenceAdaptor};
use zap_proxy::{ZapProxy, ZapPublisher, ZapSubscriber};
use zdaemon::{Api, Error as DError, Service, ZMsgExtended};

fn main() {
    let mut service: Service<Config> = try_exit(Service::load("auth.json"));

    // Create new server cert if missing
    let server_cert = match metadata(&service.get_config().unwrap().server_cert) {
        Ok(_) => try_exit(ZCert::load(&service.get_config().unwrap().server_cert)),
        Err(_) => {
            let c = try_exit(ZCert::new());
            c.set_meta("name", "auth");
            c.set_meta("type", CertType::Host.to_str());
            try_exit(c.save_public(&format!("{}_public", &service.get_config().unwrap().server_cert)));
            try_exit(c.save_secret(&service.get_config().unwrap().server_cert));
            c
        }
    };

    let mut persistence = try_exit(PersistDisk::new(&service.get_config().unwrap().cert_path));
    let cert_cache = Rc::new(RefCell::new(CertCache::new(Some(try_exit(persistence.dump())))));

    let proxy = Rc::new(try_exit(ZapProxy::new(&server_cert, service.get_config().unwrap().update_port)));

    let zap_publisher = ZapPublisher::new(proxy.clone(), cert_cache.clone());
    try_exit(service.add_endpoint(zap_publisher));

    let zap_subscriber = ZapSubscriber::new(proxy.clone(), cert_cache.clone());
    try_exit(service.add_endpoint(zap_subscriber));

    let api_sock = ZSock::new(ZSockType::REP);
    api_sock.set_zap_domain("auth.intecture");
    api_sock.set_curve_server(true);
    server_cert.apply(&api_sock);
    try_exit(api_sock.bind(&format!("tcp://*:{}", service.get_config().unwrap().api_port)));

    let api_create = Rc::new(RefCell::new(try_exit(CertApi::new(persistence, cert_cache.clone()))));
    let api_delete = api_create.clone();
    let api_list = api_create.clone();
    let api_lookup = api_create.clone();

    let mut api = Api::new(api_sock);
    api.add("cert::create", move |sock: &ZSock, endpoint_frame: ZFrame| { error_handler(sock, api_create.borrow_mut().create(sock, endpoint_frame)) });
    api.add("cert::delete", move |sock: &ZSock, endpoint_frame: ZFrame| { error_handler(sock, api_delete.borrow_mut().delete(sock, endpoint_frame)) });
    api.add("cert::list", move |sock: &ZSock, _: ZFrame| { error_handler(sock, api_list.borrow_mut().list(sock)) });
    api.add("cert::lookup", move |sock: &ZSock, _: ZFrame| { error_handler(sock, api_lookup.borrow_mut().lookup(sock)) });
    try_exit(service.add_endpoint(api));

    let _auth = ZapHandler::new(None, &server_cert, &server_cert, "127.0.0.1", service.get_config().unwrap().update_port, true);

    try_exit(service.start(None));
}

fn error_handler(sock: &ZSock, result: Result<()>) -> StdResult<(), DError> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            let derror: DError = e.into();
            let msg = try!(ZMsg::new_err(&derror));
            try!(msg.send(sock));
            Err(derror)
        }
    }
}

fn try_exit<T, E>(r: StdResult<T, E>) -> T
    where E: Into<Error> + Debug + Display {
    if let Err(e) = r {
        // XXX Logging...
        println!("{}", e);
        exit(1);
    }

    r.unwrap()
}

#[cfg(test)]
mod tests {
    use czmq::{ZMsg, ZSock};
    use error::Error;
    use super::error_handler;

    #[test]
    fn test_error_handler() {
        let client = ZSock::new_push("inproc://server_test_error_handler").unwrap();
        let server = ZSock::new_pull("inproc://server_test_error_handler").unwrap();
        server.set_rcvtimeo(Some(500));

        assert!(error_handler(&client, Err(Error::Forbidden)).is_err());

        let msg = ZMsg::recv(&server).unwrap();
        assert_eq!(msg.popstr().unwrap().unwrap(), "Err");
        assert_eq!(msg.popstr().unwrap().unwrap(), "Access to this endpoint is forbidden");
    }
}
