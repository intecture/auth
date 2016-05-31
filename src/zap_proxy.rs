// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use cert::CertType;
use cert_cache::CertCache;
use czmq::{ZCert, ZFrame, ZSock, ZSockType};
use error::Result;
use std::cell::RefCell;
use std::rc::Rc;
use std::result::Result as StdResult;
use std::str;
use zdaemon::{Endpoint, Error as DError};

pub struct ZapProxy {
    publisher: ZSock,
    subscriber: ZSock,
    cache: Rc<RefCell<CertCache>>,
}

impl ZapProxy {
    pub fn new(cert: &ZCert, update_port: u32, cache: Rc<RefCell<CertCache>>) -> Result<ZapProxy> {
        let xpub = ZSock::new(ZSockType::XPUB);
        xpub.set_zap_domain("auth.intecture");
        xpub.set_curve_server(true);
        cert.apply(&xpub);
        try!(xpub.bind(&format!("tcp://*:{}", update_port)));

        let xsub = try!(ZSock::new_xsub("inproc://auth_publisher"));

        Ok(ZapProxy {
            publisher: xpub,
            subscriber: xsub,
            cache: cache,
        })
    }
}

pub struct ZapPublisher {
    proxy: Rc<ZapProxy>,
}

impl ZapPublisher {
    pub fn new(proxy: Rc<ZapProxy>) -> ZapPublisher {
        ZapPublisher {
            proxy: proxy,
        }
    }
}

impl Endpoint for ZapPublisher {
    fn get_socket(&self) -> &ZSock {
        &self.proxy.publisher
    }

    fn recv(&mut self) -> StdResult<(), DError> {
        let frame = try!(ZFrame::recv(&self.proxy.publisher));

        let bytes = match try!(frame.data()) {
            Ok(s) => s.into_bytes(),
            Err(b) => b,
        };

        if let Some((event, topic_bytes)) = bytes.split_first() {
            // Only send cache on subscribe ("1"), not unsubscribe ("0")
            if event == &1 {
                let cert_type = if topic_bytes.len() == 0 {
                    None
                } else {
                    let topic = try!(str::from_utf8(&topic_bytes));
                    Some(try!(CertType::from_str(topic)))
                };
                try!(self.proxy.cache.borrow().send(&self.proxy.publisher, cert_type));
            }
        }

        // Pass subscription frame to publisher
        try!(frame.send(&self.proxy.subscriber, None));

        Ok(())
    }
}

pub struct ZapSubscriber {
    proxy: Rc<ZapProxy>,
}

impl ZapSubscriber {
    pub fn new(proxy: Rc<ZapProxy>) -> ZapSubscriber {
        ZapSubscriber {
            proxy: proxy,
        }
    }
}

impl Endpoint for ZapSubscriber {
    fn get_socket(&self) -> &ZSock {
        &self.proxy.publisher
    }

    fn recv(&mut self) -> StdResult<(), DError> {
        // Cache certificate
        let proxy = Rc::get_mut(&mut self.proxy).unwrap();
        let msg = try!(proxy.cache.borrow_mut().recv(&proxy.subscriber));

        // Forward message to subscriber
        try!(msg.send(&proxy.publisher));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cert::{Cert, CertType};
    use cert_cache::CertCache;
    use czmq::{zsys_init, ZFrame, ZMsg, ZSock, ZSockType};
    use std::cell::RefCell;
    use std::rc::Rc;
    use super::*;
    use zdaemon::Endpoint;

    #[test]
    fn test_publisher() {
        zsys_init();

        let user_cert = Cert::new("john.smith", CertType::User).unwrap();
        let user_pubkey = user_cert.public_txt().to_string();
        let user_meta = user_cert.encode_meta();

        let host_cert = Cert::new("example.com", CertType::Host).unwrap();
        let host_pubkey = host_cert.public_txt().to_string();
        let host_meta = host_cert.encode_meta();

        let cache = CertCache::new(Some(vec![
            user_cert,
            host_cert,
        ]));

        let xpub = ZSock::new_xpub("inproc://zap_proxy_test_publisher").unwrap();
        xpub.set_sndtimeo(Some(500));
        xpub.set_rcvtimeo(Some(500));
        let xsub = ZSock::new(ZSockType::XSUB);

        let proxy = Rc::new(ZapProxy {
            publisher: xpub,
            subscriber: xsub,
            cache: Rc::new(RefCell::new(cache)),
        });

        let mut publisher = ZapPublisher::new(proxy);

        let client = ZSock::new_sub("inproc://zap_proxy_test_publisher", Some("user")).unwrap();
        client.set_rcvtimeo(Some(500));

        publisher.recv().unwrap();
        let msg = ZMsg::recv(&client).unwrap();
        msg.popstr().unwrap().unwrap(); // Discard topic
        assert_eq!(msg.popstr().unwrap().unwrap(), "ADD");
        assert_eq!(msg.popstr().unwrap().unwrap(), user_pubkey);
        assert_eq!(msg.popbytes().unwrap().unwrap(), user_meta);

        client.set_unsubscribe("user");
        publisher.recv().unwrap();
        assert!(client.recv_str().is_err());

        client.set_subscribe("");
        publisher.recv().unwrap();
        let msg = ZMsg::recv(&client).unwrap();
        msg.popstr().unwrap().unwrap(); // Discard topic
        assert_eq!(msg.popstr().unwrap().unwrap(), "ADD");

        let pk1 = msg.popstr().unwrap().unwrap();
        let md1 = msg.popbytes().unwrap().unwrap();
        let pk2 = msg.popstr().unwrap().unwrap();
        let md2 = msg.popbytes().unwrap().unwrap();
        let check = (pk1 == user_pubkey && md1 == user_meta && pk2 == host_pubkey && md2 == host_meta) ||
                    (pk1 == host_pubkey && md1 == host_meta && pk2 == user_pubkey && md2 == user_meta);
        assert!(check);
    }

    #[test]
    fn test_subscriber() {
        zsys_init();

        let user_cert = Cert::new("john.smith", CertType::User).unwrap();
        let user_pubkey = user_cert.public_txt().to_string();
        let user_meta = user_cert.encode_meta();

        let host_cert = Cert::new("example.com", CertType::Host).unwrap();
        let host_pubkey = host_cert.public_txt().to_string();
        let host_meta = host_cert.encode_meta();

        let cache = CertCache::new(None);

        let xpub = ZSock::new(ZSockType::XPUB);
        let xsub = ZSock::new_xsub("@inproc://zap_proxy_test_subscriber").unwrap();
        xsub.set_rcvtimeo(Some(500));

        let proxy = Rc::new(ZapProxy {
            publisher: xpub,
            subscriber: xsub,
            cache: Rc::new(RefCell::new(cache)),
        });

        let mut subscriber = ZapSubscriber::new(proxy);

        let server = ZSock::new_pub(">inproc://zap_proxy_test_subscriber").unwrap();
        server.set_sndtimeo(Some(500));

        let subscribe_frame = ZFrame::new(&[1]).unwrap();
        subscribe_frame.send(&subscriber.proxy.subscriber, None).unwrap();

        let msg = ZMsg::new();
        msg.addstr("user").unwrap();
        msg.addstr("ADD").unwrap();
        msg.addstr(&user_pubkey).unwrap();
        msg.addbytes(&user_meta).unwrap();
        msg.send(&server).unwrap();

        subscriber.recv().unwrap();
        assert!(subscriber.proxy.cache.borrow().get(&user_pubkey).is_some());

        let msg = ZMsg::new();
        msg.addstr("host").unwrap();
        msg.addstr("ADD").unwrap();
        msg.addstr(&host_pubkey).unwrap();
        msg.addbytes(&host_meta).unwrap();
        msg.send(&server).unwrap();

        subscriber.recv().unwrap();
        assert!(subscriber.proxy.cache.borrow().get(&host_pubkey).is_some());
    }
}
