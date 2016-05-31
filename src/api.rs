// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use cert::{Cert, CertType};
use cert_cache::CertCache;
use czmq::{ZFrame, ZMsg, ZSock};
use error::{Error, Result};
use zmsg::ZMsgExtended;
use std::cell::RefCell;
use std::rc::Rc;
use storage::PersistenceAdaptor;
use request_meta::RequestMeta;

pub struct CertApi<P> {
    persistence: P,
    publisher: ZSock,
    cert_cache: Rc<RefCell<CertCache>>,
}

impl<P> CertApi<P> where P: PersistenceAdaptor {
    pub fn new(persistence: P, cert_cache: Rc<RefCell<CertCache>>) -> Result<CertApi<P>> {
        Ok(CertApi {
            persistence: persistence,
            publisher: try!(ZSock::new_pub(">inproc://auth_publisher")),
            cert_cache: cert_cache,
        })
    }

    pub fn lookup(&mut self, sock: &ZSock) -> Result<()> {
        let msg = try!(ZMsg::expect_recv(sock, 1, Some(1), false));
        let name = match msg.popstr().unwrap() {
            Ok(str) => str,
            Err(_) => return Err(Error::InvalidArg),
        };

        match self.cert_cache.borrow().get_name(&name) {
            Some(cert) => {
                let reply = try!(ZMsg::new_ok());
                try!(reply.addstr(cert.public_txt()));
                try!(reply.send(sock));
                Ok(())
            },
            None => Err(Error::InvalidCert),
        }
    }

    pub fn create(&mut self, sock: &ZSock, endpoint_frame: ZFrame) -> Result<()> {
        // Only users can create certificates
        let meta = try!(RequestMeta::new(&endpoint_frame));
        if meta.cert_type != CertType::User {
            return Err(Error::Forbidden);
        }

        self.do_create(sock)
    }

    // Allow testing without auth
    fn do_create(&mut self, sock: &ZSock) -> Result<()> {
        let request = try!(ZMsg::expect_recv(sock, 2, Some(2), false));

        let cert_type = match request.popstr().unwrap() {
            Ok(t) => try!(CertType::from_str(&t)),
            Err(_) => return Err(Error::InvalidCertMeta),
        };

        let cert_name = match request.popstr().unwrap() {
            Ok(n) => n,
            Err(_) => return Err(Error::InvalidCertMeta),
        };

        let cert = try!(Cert::new(&cert_name, cert_type));
        try!(self.persistence.create(&cert));

        // Publish cert
        let msg = ZMsg::new();
        try!(msg.addstr(cert.cert_type().to_str()));
        try!(msg.addstr("ADD"));
        try!(msg.addstr(cert.public_txt()));
        try!(msg.addbytes(&cert.encode_meta()));
        try!(msg.send(&self.publisher));

        // Reply cert
        let msg = try!(ZMsg::new_ok());
        try!(msg.addstr(cert.public_txt()));
        try!(msg.addstr(cert.secret_txt()));
        try!(msg.addbytes(&cert.encode_meta()));
        try!(msg.send(sock));

        Ok(())
    }

    pub fn delete(&mut self, sock: &ZSock, endpoint_frame: ZFrame) -> Result<()> {
        // Only users can delete certificates
        let meta = try!(RequestMeta::new(&endpoint_frame));
        if meta.cert_type != CertType::User {
            return Err(Error::Forbidden);
        }

        self.do_delete(sock)
    }

    // Allow testing without auth
    fn do_delete(&mut self, sock: &ZSock) -> Result<()> {
        let request = try!(ZMsg::expect_recv(sock, 1, Some(1), false));
        let pubkey: String = match request.popstr().unwrap() {
            Ok(n) => n,
            Err(_) => return Err(Error::InvalidCert),
        };

        let cert = try!(self.persistence.read_pubkey(&pubkey));

        try!(self.persistence.delete(&pubkey));

        try!(ZMsg::send_multi(&self.publisher, &[
            cert.cert_type().to_str(),
            "DEL",
            &pubkey,
        ]));

        try!(sock.send_str("Ok"));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cert::{Cert, CertType};
    use cert_cache::CertCache;
    use czmq::{zsys_init, ZMsg, ZSock};
    use std::cell::RefCell;
    use std::rc::Rc;
    use storage::{PersistenceAdaptor, PersistDisk};
    use super::*;
    use tempdir::TempDir;
    use zmsg::ZMsgExtended;

    #[test]
    fn test_lookup() {
        zsys_init();

        let cert = Cert::new("r2d2", CertType::Host).unwrap();
        let (_dir, mut api) = create_api(">inproc://api_test_lookup_publisher", Some(&cert));

        let client = ZSock::new_req("inproc://api_test_lookup").unwrap();
        let server = ZSock::new_rep("inproc://api_test_lookup").unwrap();

        client.send_str("Han Solo").unwrap();
        assert!(api.lookup(&server).is_err());
        server.send_str("").unwrap();
        client.recv_str().unwrap().unwrap();

        client.send_str("r2d2").unwrap();
        assert!(api.lookup(&server).is_ok());

        let reply = ZMsg::recv(&client).unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");
        assert_eq!(reply.popstr().unwrap().unwrap(), cert.public_txt());
    }

    #[test]
    fn test_create() {
        zsys_init();

        let (_dir, mut api) = create_api(">inproc://api_test_create_publisher", None);

        let subscriber = ZSock::new_sub("@inproc://api_test_create_publisher", Some("host")).unwrap();
        let client = ZSock::new_req("inproc://api_test_create").unwrap();
        let server = ZSock::new_rep("inproc://api_test_create").unwrap();

        ZMsg::send_multi(&client, &["host", "usetheforks.com"]).unwrap();
        assert!(api.do_create(&server).is_ok());

        let reply = ZMsg::recv(&client).unwrap();
        assert_eq!(reply.size(), 4);
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");
        let pubkey = reply.popstr().unwrap().unwrap();

        let sub_reply = ZMsg::recv(&subscriber).unwrap();
        sub_reply.popstr().unwrap().unwrap(); // Remove topic frame
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), "ADD");
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), pubkey);
    }

    #[test]
    fn test_delete() {
        zsys_init();

        let cert = Cert::new("c3po", CertType::Host).unwrap();
        let (_dir, mut api) = create_api(">inproc://api_test_delete_publisher", Some(&cert));

        let subscriber = ZSock::new_sub("@inproc://api_test_delete_publisher", Some("host")).unwrap();
        let client = ZSock::new_req("inproc://api_test_delete").unwrap();
        let server = ZSock::new_rep("inproc://api_test_delete").unwrap();

        client.send_str("Han Solo's Millenium Falcon Ignition Key").unwrap();
        assert!(api.do_delete(&server).is_err());
        server.send_str("").unwrap();
        client.recv_str().unwrap().unwrap();

        client.send_str(cert.public_txt()).unwrap();
        assert!(api.do_delete(&server).is_ok());

        let reply = ZMsg::recv(&client).unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");

        let sub_reply = ZMsg::recv(&subscriber).unwrap();
        sub_reply.popstr().unwrap().unwrap(); // Remove topic frame
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), "DEL");
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), cert.public_txt());
    }

    fn create_api(endpoint: &str, cert: Option<&Cert>) -> (TempDir, CertApi<PersistDisk>) {
        let dir = TempDir::new("test_api").unwrap();

        let mut disk = PersistDisk::new(dir.path().to_str().unwrap()).unwrap();
        if let Some(cert) = cert {
            disk.create(cert).unwrap();
        }

        let cert_cache = Rc::new(RefCell::new(CertCache::new(Some(disk.dump().unwrap()))));
        let api = CertApi {
            persistence: disk,
            publisher: ZSock::new_pub(endpoint).unwrap(),
            cert_cache: cert_cache,
        };
        (dir, api)
    }
}
