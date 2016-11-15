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
use std::cell::RefCell;
use std::rc::Rc;
use storage::PersistenceAdaptor;
use request_meta::RequestMeta;
use zdaemon::ZMsgExtended;

pub struct CertApi<P> {
    persistence: P,
    publisher: ZSock,
    cert_cache: Rc<RefCell<CertCache>>,
}

impl<P> CertApi<P> where P: PersistenceAdaptor {
    pub fn new(persistence: P, cert_cache: Rc<RefCell<CertCache>>) -> Result<CertApi<P>> {
        Ok(CertApi {
            persistence: persistence,
            publisher: ZSock::new_pub("inproc://auth_publisher")?,
            cert_cache: cert_cache,
        })
    }

    pub fn list(&mut self, sock: &mut ZSock, router_id: &[u8]) -> Result<()> {
        let msg = ZMsg::expect_recv(sock, 1, Some(1), false)?;
        let cert_type = match msg.popstr().unwrap() {
            Ok(str) => str,
            Err(_) => return Err(Error::InvalidArg),
        };

        let reply = ZMsg::new_ok()?;
        reply.pushbytes(router_id)?;
        for cert in self.cert_cache.borrow().dump(CertType::from_str(&cert_type)?) {
            reply.addstr(cert.name())?;
        }
        reply.send(sock)?;
        Ok(())
    }

    pub fn lookup(&mut self, sock: &mut ZSock, router_id: &[u8]) -> Result<()> {
        let msg = ZMsg::expect_recv(sock, 1, Some(1), false)?;
        let name = match msg.popstr().unwrap() {
            Ok(str) => str,
            Err(_) => return Err(Error::InvalidArg),
        };

        match self.cert_cache.borrow().get_name(&name) {
            Some(cert) => {
                let reply = ZMsg::new_ok()?;
                reply.pushbytes(router_id)?;
                reply.addstr(cert.public_txt())?;
                reply.send(sock)?;
                Ok(())
            },
            None => Err(Error::InvalidCert),
        }
    }

    pub fn create(&mut self, sock: &mut ZSock, endpoint_frame: ZFrame, router_id: &[u8]) -> Result<()> {
        // Only users can create certificates
        let meta = RequestMeta::new(&endpoint_frame)?;
        if meta.cert_type != CertType::User {
            return Err(Error::Forbidden);
        }

        self.do_create(sock, router_id)
    }

    // Allow testing without auth
    fn do_create(&mut self, sock: &mut ZSock, router_id: &[u8]) -> Result<()> {
        let request = ZMsg::expect_recv(sock, 2, Some(2), false)?;

        let cert_type = match request.popstr().unwrap() {
            Ok(t) => CertType::from_str(&t)?,
            Err(_) => return Err(Error::InvalidCertMeta),
        };

        let cert_name = match request.popstr().unwrap() {
            Ok(n) => n,
            Err(_) => return Err(Error::InvalidCertMeta),
        };

        let cert = Cert::new(&cert_name, cert_type)?;
        self.persistence.create(&cert)?;

        // Publish cert
        let msg = ZMsg::new();
        msg.addstr(cert.cert_type().to_str())?;
        msg.addstr("ADD")?;
        msg.addstr(cert.public_txt())?;
        msg.addbytes(&cert.encode_meta())?;
        msg.send(&mut self.publisher)?;

        // Reply cert
        let msg = ZMsg::new_ok()?;
        msg.pushbytes(router_id)?;
        msg.addstr(cert.public_txt())?;
        msg.addstr(cert.secret_txt())?;
        msg.addbytes(&cert.encode_meta())?;
        msg.send(sock)?;

        Ok(())
    }

    pub fn delete(&mut self, sock: &mut ZSock, endpoint_frame: ZFrame, router_id: &[u8]) -> Result<()> {
        // Only users can delete certificates
        let meta = RequestMeta::new(&endpoint_frame)?;
        if meta.cert_type != CertType::User {
            return Err(Error::Forbidden);
        }

        self.do_delete(sock, router_id)
    }

    // Allow testing without auth
    fn do_delete(&mut self, sock: &mut ZSock, router_id: &[u8]) -> Result<()> {
        let request = ZMsg::expect_recv(sock, 1, Some(1), false)?;
        let name: String = match request.popstr().unwrap() {
            Ok(n) => n,
            Err(_) => return Err(Error::InvalidCert),
        };

        let cert = self.persistence.read(&name)?;

        self.persistence.delete(&name)?;

        let msg = ZMsg::new();
        msg.send_multi(&mut self.publisher, &[
            cert.cert_type().to_str(),
            "DEL",
            &cert.public_txt(),
        ])?;

        let msg = ZMsg::new_ok()?;
        msg.pushbytes(router_id)?;
        msg.send(sock)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cert::{Cert, CertType};
    use cert_cache::CertCache;
    use czmq::{ZMsg, ZSock, ZSys};
    use std::cell::RefCell;
    use std::rc::Rc;
    use storage::{PersistenceAdaptor, PersistDisk};
    use super::*;
    use tempdir::TempDir;
    use zdaemon::ZMsgExtended;

    #[test]
    fn test_list() {
        ZSys::init();

        let host = Cert::new("luke.jedi.org", CertType::Host).unwrap();
        let user = Cert::new("luke_vader", CertType::User).unwrap();
        let (_dir, mut api) = create_api(">inproc://api_test_list_publisher", Some(vec![&host, &user]));

        let (mut client, mut server) = ZSys::create_pipe().unwrap();

        client.send_str("user").unwrap();
        api.list(&mut server, b"router_id").unwrap();

        let reply = ZMsg::recv(&mut client).unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "router_id");
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");
        assert_eq!(reply.popstr().unwrap().unwrap(), "luke_vader");

        client.send_str("host").unwrap();
        api.list(&mut server, b"router_id").unwrap();

        let reply = ZMsg::recv(&mut client).unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "router_id");
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");
        assert_eq!(reply.popstr().unwrap().unwrap(), "luke.jedi.org");
    }

    #[test]
    fn test_lookup() {
        ZSys::init();

        let cert = Cert::new("r2d2", CertType::Host).unwrap();
        let (_dir, mut api) = create_api(">inproc://api_test_lookup_publisher", Some(vec![&cert]));

        let mut client = ZSock::new_req("inproc://api_test_lookup").unwrap();
        let mut server = ZSock::new_rep("inproc://api_test_lookup").unwrap();

        client.send_str("Han Solo").unwrap();
        assert!(api.lookup(&mut server, b"router_id").is_err());
        server.send_str("").unwrap();
        client.recv_str().unwrap().unwrap();

        client.send_str("r2d2").unwrap();
        assert!(api.lookup(&mut server, b"router_id").is_ok());

        let reply = ZMsg::recv(&mut client).unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "router_id");
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");
        assert_eq!(reply.popstr().unwrap().unwrap(), cert.public_txt());
    }

    #[test]
    fn test_create() {
        ZSys::init();

        let (_dir, mut api) = create_api(">inproc://api_test_create_publisher", None);

        let mut subscriber = ZSock::new_sub("@inproc://api_test_create_publisher", Some("host")).unwrap();
        let mut client = ZSock::new_req("inproc://api_test_create").unwrap();
        let mut server = ZSock::new_rep("inproc://api_test_create").unwrap();

        let msg = ZMsg::new();
        msg.send_multi(&mut client, &["host", "usetheforks.com"]).unwrap();
        api.do_create(&mut server, b"router_id").unwrap();

        let reply = ZMsg::recv(&mut client).unwrap();
        assert_eq!(reply.size(), 5);
        assert_eq!(reply.popstr().unwrap().unwrap(), "router_id");
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");
        let pubkey = reply.popstr().unwrap().unwrap();

        let sub_reply = ZMsg::recv(&mut subscriber).unwrap();
        sub_reply.popstr().unwrap().unwrap(); // Remove topic frame
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), "ADD");
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), pubkey);
    }

    #[test]
    fn test_delete() {
        ZSys::init();

        let cert = Cert::new("c3po", CertType::Host).unwrap();
        let (_dir, mut api) = create_api(">inproc://api_test_delete_publisher", Some(vec![&cert]));

        let mut subscriber = ZSock::new_sub("@inproc://api_test_delete_publisher", Some("host")).unwrap();
        let mut client = ZSock::new_req("inproc://api_test_delete").unwrap();
        let mut server = ZSock::new_rep("inproc://api_test_delete").unwrap();

        client.send_str("Han Solo's Millenium Falcon Ignition Key").unwrap();
        assert!(api.do_delete(&mut server, b"router_id").is_err());
        server.send_str("").unwrap();
        client.recv_str().unwrap().unwrap();

        client.send_str("c3po").unwrap();
        assert!(api.do_delete(&mut server, b"router_id").is_ok());

        let reply = ZMsg::recv(&mut client).unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "router_id");
        assert_eq!(reply.popstr().unwrap().unwrap(), "Ok");

        let sub_reply = ZMsg::recv(&mut subscriber).unwrap();
        sub_reply.popstr().unwrap().unwrap(); // Remove topic frame
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), "DEL");
        assert_eq!(sub_reply.popstr().unwrap().unwrap(), cert.public_txt());
    }

    fn create_api(endpoint: &str, certs: Option<Vec<&Cert>>) -> (TempDir, CertApi<PersistDisk>) {
        let dir = TempDir::new("test_api").unwrap();

        let mut disk = PersistDisk::new(dir.path().to_str().unwrap()).unwrap();
        if let Some(certs) = certs {
            for cert in certs {
                disk.create(cert).unwrap();
            }
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
