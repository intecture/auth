// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use cert::CertType;
use cert_cache::CertCache;
use czmq::{ZCert, ZFrame, ZMsg, ZSock, SocketType, ZSys};
use error::Result;
use std::cell::RefCell;
use std::rc::Rc;
use std::result::Result as StdResult;
use std::str;
use zdaemon::{Endpoint, Error as DError, ZMsgExtended};

pub fn init(cert: &ZCert, update_port: u32, cert_cache: Rc<RefCell<CertCache>>) -> Result<(ZapPublisher, ZapSubscriber)> {
    let mut xpub = ZSock::new(SocketType::XPUB);
    xpub.set_xpub_verbose(true);
    xpub.set_zap_domain("auth.intecture");
    xpub.set_curve_server(true);
    cert.apply(&mut xpub);
    try!(xpub.bind(&format!("tcp://*:{}", update_port)));

    let xsub = try!(ZSock::new_xsub("inproc://auth_publisher"));

    let (s_pipe, p_pipe) = try!(ZSys::create_pipe());

    Ok((
        ZapPublisher {
            publisher: xpub,
            subscriber: s_pipe,
            cache: cert_cache.clone(),
        },
        ZapSubscriber {
            subscriber: xsub,
            publisher: p_pipe,
            cache: cert_cache,
        }
    ))
}

pub struct ZapPublisher {
    publisher: ZSock,
    subscriber: ZSock,
    cache: Rc<RefCell<CertCache>>,
}

impl Endpoint for ZapPublisher {
    fn get_sockets(&mut self) -> Vec<&mut ZSock> {
        vec![&mut self.publisher, &mut self.subscriber]
    }

    fn recv(&mut self, sock: &mut ZSock) -> StdResult<(), DError> {
        if *sock == self.publisher {
            let frame = try!(ZFrame::recv(&mut self.publisher));

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
                    try!(self.cache.borrow().send(&mut self.publisher, cert_type));
                }
            }

            // Receive any unreceived frames
            let msg = try!(ZMsg::expect_recv(&mut self.publisher, 0, None, false));
            try!(msg.prepend(frame));

            // Pass subscription frame to publishers
            try!(msg.send(&mut self.subscriber));
        }
        else if *sock == self.subscriber {
            let msg = try!(ZMsg::recv(sock));
            try!(msg.send(&mut self.publisher));
        }
        else {
            unreachable!();
        }
        Ok(())
    }
}

pub struct ZapSubscriber {
    subscriber: ZSock,
    publisher: ZSock,
    cache: Rc<RefCell<CertCache>>,
}

impl Endpoint for ZapSubscriber {
    fn get_sockets(&mut self) -> Vec<&mut ZSock> {
        vec![&mut self.subscriber, &mut self.publisher]
    }

    fn recv(&mut self, sock: &mut ZSock) -> StdResult<(), DError> {
        if *sock == self.subscriber {
            // Cache certificate
            let msg = try!(self.cache.borrow_mut().recv(&mut self.subscriber));

            // Forward message to subscriber (XPUB)
            try!(msg.send(&mut self.publisher));
        }
        else if *sock == self.publisher {
            let msg = try!(ZMsg::recv(sock));
            try!(msg.send(&mut self.subscriber));
        }
        else {
            unreachable!();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cert::{Cert, CertType};
    use cert_cache::CertCache;
    use czmq::{RawInterface, ZMsg, ZSock, ZSys};
    use std::cell::RefCell;
    use std::rc::Rc;
    use super::*;
    use zdaemon::Endpoint;

    #[test]
    fn test_pubsub() {
        ZSys::init();

        let user_cert = Cert::new("john.smith", CertType::User).unwrap();
        let user_pubkey = user_cert.public_txt().to_string();
        let user_meta = user_cert.encode_meta();

        let host_cert = Cert::new("example.com", CertType::Host).unwrap();
        let host_pubkey = host_cert.public_txt().to_string();
        let host_meta = host_cert.encode_meta();

        let cache = Rc::new(RefCell::new(CertCache::new(Some(vec![ user_cert ]))));

        let mut xpub = ZSock::new_xpub("inproc://zap_proxy_test_publisher").unwrap();
        xpub.set_sndtimeo(Some(500));
        xpub.set_rcvtimeo(Some(500));
        let mut xpub_clone = unsafe { ZSock::from_raw(xpub.as_mut_ptr(), false) };

        let mut xsub = ZSock::new_xsub("@inproc://zap_proxy_test_subscriber").unwrap();
        xsub.set_sndtimeo(Some(500));
        xsub.set_rcvtimeo(Some(500));
        let mut xsub_clone = unsafe { ZSock::from_raw(xsub.as_mut_ptr(), false) };

        let (mut s_pair, mut p_pair) = ZSys::create_pipe().unwrap();
        let mut s_pair_clone = unsafe { ZSock::from_raw(s_pair.as_mut_ptr(), false) };
        let mut p_pair_clone = unsafe { ZSock::from_raw(p_pair.as_mut_ptr(), false) };

        let mut publisher = ZapPublisher {
            publisher: xpub,
            subscriber: s_pair,
            cache: cache.clone(),
        };

        let mut subscriber = ZapSubscriber {
            subscriber: xsub,
            publisher: p_pair,
            cache: cache,
        };

        let mut server = ZSock::new_pub(">inproc://zap_proxy_test_subscriber").unwrap();
        server.set_sndtimeo(Some(500));

        let mut client = ZSock::new_sub("inproc://zap_proxy_test_publisher", Some("user")).unwrap();
        client.set_rcvtimeo(Some(500));

        publisher.recv(&mut xpub_clone).unwrap();
        subscriber.recv(&mut p_pair_clone).unwrap();
        let msg = ZMsg::recv(&mut client).unwrap();
        msg.popstr().unwrap().unwrap(); // Discard topic
        assert_eq!(msg.popstr().unwrap().unwrap(), "ADD");
        assert_eq!(msg.popstr().unwrap().unwrap(), user_pubkey);
        assert_eq!(msg.popbytes().unwrap().unwrap(), user_meta);

        client.set_unsubscribe("user");
        publisher.recv(&mut xpub_clone).unwrap();
        subscriber.recv(&mut p_pair_clone).unwrap();
        assert!(client.recv_str().is_err());

        client.set_subscribe("");
        publisher.recv(&mut xpub_clone).unwrap();
        subscriber.recv(&mut p_pair_clone).unwrap();
        client.recv_str().unwrap().unwrap(); // Receive user cert again
        client.flush();

        let msg = ZMsg::new();
        msg.addstr("host").unwrap();
        msg.addstr("ADD").unwrap();
        msg.addstr(&host_pubkey).unwrap();
        msg.addbytes(&host_meta).unwrap();
        msg.send(&mut server).unwrap();

        subscriber.recv(&mut xsub_clone).unwrap();
        publisher.recv(&mut s_pair_clone).unwrap();
        assert!(subscriber.cache.borrow().get(&host_pubkey).is_some());

        let msg = ZMsg::recv(&mut client).unwrap();
        msg.popstr().unwrap().unwrap(); // Discard topic
        assert_eq!(msg.popstr().unwrap().unwrap(), "ADD");
        assert_eq!(msg.popstr().unwrap().unwrap(), host_pubkey);
        assert_eq!(msg.popbytes().unwrap().unwrap(), host_meta);
    }
}
