// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.
use cert::{Cert, CertType};
use czmq::{ZCert, ZMsg, ZSock};
use error::{Error, Result};
use std::collections::HashMap;

pub struct CertCache {
    cache: HashMap<String, Cert>,
}

impl CertCache {
    pub fn new(certs: Option<Vec<Cert>>) -> CertCache {
        let mut cache = HashMap::new();

        // Warm up cache
        if let Some(certs) = certs {
            for cert in certs {
                cache.insert(cert.public_txt().to_string(), cert);
            }
        }

        CertCache {
            cache: cache,
        }
    }

    // This is only used by the client
    #[allow(dead_code)]
    pub fn get(&self, pubkey: &str) -> Option<&Cert> {
        self.cache.get(pubkey)
    }

    // This is only used by the server
    #[allow(dead_code)]
    pub fn get_name(&self, name: &str) -> Option<&Cert> {
        for (_, cert) in &self.cache {
            if cert.name() == name {
                return Some(cert);
            }
        }

        None
    }

    pub fn dump(&self, cert_type: CertType) -> Vec<&Cert> {
        let mut dump = Vec::new();

        for (_, cert) in &self.cache {
            if cert.cert_type() == cert_type {
                dump.push(cert);
            }
        }

        dump
    }

    pub fn send(&self, sock: &ZSock, topic: Option<CertType>) -> Result<()> {
        let msg = ZMsg::new();
        match topic {
            Some(cert_type) => try!(msg.addstr(cert_type.to_str())),
            None => try!(msg.addstr("")),
        }
        try!(msg.addstr("ADD"));

        for (_, cert) in &self.cache {
            if topic.is_none() || cert.cert_type() == topic.unwrap() {
                try!(msg.addstr(cert.public_txt()));
                try!(msg.addbytes(&cert.encode_meta()));
            }
        }

        if msg.size() > 2 {
            try!(msg.send(sock));
        }

        Ok(())
    }

    pub fn recv(&mut self, sock: &ZSock) -> Result<ZMsg> {
        let msg = try!(ZMsg::recv(sock));

        // Remove topic frame
        try!(msg.next().ok_or(Error::InvalidCertFeed));

        let action = match try!(try!(msg.next().ok_or(Error::InvalidCertFeed)).data()) {
            Ok(s) => s,
            Err(_) => return Err(Error::InvalidCertFeed),
        };

        match action.as_ref() {
            "ADD" => {
                while let Some(frame) = msg.next() {
                    let pubkey = match try!(frame.data()) {
                        Ok(s) => s,
                        Err(_) => return Err(Error::InvalidCertFeed),
                    };

                    if let Some(frame) = msg.next() {
                        let meta = match try!(frame.data()) {
                            Ok(s) => s.into_bytes(),
                            Err(b) => b,
                        };

                        let zcert = ZCert::from_txt(&pubkey, "0000000000000000000000000000000000000000");
                        try!(zcert.decode_meta(&meta));

                        self.cache.insert(zcert.public_txt().to_string(), try!(Cert::from_zcert(zcert)));
                    } else {
                        break;
                    }
                }
            },
            "DEL" => {
                let pubkey = match try!(try!(msg.next().ok_or(Error::InvalidCertFeed)).data()) {
                    Ok(s) => s,
                    Err(_) => return Err(Error::InvalidCertFeed),
                };

                self.cache.remove(&pubkey);
            },
            _ => return Err(Error::InvalidCertFeed),
        }

        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use cert::{Cert, CertType};
    use czmq::{ZCert, ZMsg, ZSock};
    use super::*;

    #[test]
    fn test_get() {
        let (cache, pubkey) = create_cache();

        assert!(cache.get("nonexistent").is_none());
        assert_eq!(cache.get(&pubkey).unwrap().public_txt(), &pubkey);
    }

    #[test]
    fn test_get_name() {
        let (cache, _) = create_cache();

        assert!(cache.get_name("nonexistent").is_none());
        assert_eq!(cache.get_name("peetar!").unwrap().name(), "peetar!");
    }

    #[test]
    fn test_send() {
        let (cache, pubkey) = create_cache();

        let client = ZSock::new_push("inproc://cert_cache_send").unwrap();
        let server = ZSock::new_pull("inproc://cert_cache_send").unwrap();
        server.set_rcvtimeo(Some(500));

        cache.send(&client, Some(CertType::Host)).unwrap();
        assert!(server.recv_str().is_err());

        cache.send(&client, Some(CertType::User)).unwrap();
        let msg = ZMsg::recv(&server).unwrap();
        msg.popstr().unwrap().unwrap(); // Discard topic
        assert_eq!(msg.popstr().unwrap().unwrap(), "ADD");
        assert_eq!(msg.popstr().unwrap().unwrap(), pubkey);

        let zcert = ZCert::new().unwrap();
        zcert.decode_meta(&msg.popbytes().unwrap().unwrap()).unwrap();
        assert_eq!(zcert.meta("name").unwrap().unwrap(), "peetar!");
        assert_eq!(zcert.meta("type").unwrap().unwrap(), "user");
    }

    #[test]
    fn test_recv() {
        let mut cache = CertCache::new(None);
        let c1 = Cert::new("dan", CertType::User).unwrap();
        let c2 = Cert::new("web1.example.com", CertType::Host).unwrap();

        let client = ZSock::new_push("inproc://cert_cache_recv").unwrap();
        let server = ZSock::new_pull("inproc://cert_cache_recv").unwrap();
        server.set_rcvtimeo(Some(500));

        assert!(cache.recv(&server).is_err());

        let msg = ZMsg::new();
        msg.addstr("topic").unwrap();
        msg.addstr("ADD").unwrap();
        msg.addstr(c1.public_txt()).unwrap();
        msg.addbytes(&c1.encode_meta()).unwrap();
        msg.addstr(c2.public_txt()).unwrap();
        msg.addbytes(&c2.encode_meta()).unwrap();
        msg.send(&client).unwrap();

        assert!(cache.recv(&server).is_ok());
        assert!(cache.cache.contains_key(c1.public_txt()));
        assert!(cache.cache.contains_key(c2.public_txt()));

        let msg = ZMsg::new();
        msg.addstr("topic").unwrap();
        msg.addstr("DEL").unwrap();
        msg.addstr(c1.public_txt()).unwrap();
        msg.send(&client).unwrap();

        assert!(cache.recv(&server).is_ok());
        assert!(!cache.cache.contains_key(c1.public_txt()));
    }

    fn create_cache() -> (CertCache, String) {
        let cert = Cert::new("peetar!", CertType::User).unwrap();
        let pubkey = cert.public_txt().to_string();

        (CertCache::new(Some(vec![cert])), pubkey)
    }
}
