// Copyright 2015-2017 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use cert::{Cert, CertType};
use cert_cache::CertCache;
use czmq::{ZCert, ZFrame, ZMsg, ZPoller, ZSock, SocketType, ZSys};
use error::{Error, Result};
use std::fmt;
use std::thread::{JoinHandle, spawn};
use zdaemon::ZMsgExtended;
use zmq::z85_encode;

const ZAP_ENDPOINT: &'static str = "inproc://zeromq.zap.01";
const THREAD_TERM: &'static str = "$TERM";

pub struct ZapHandler {
    worker: Option<JoinHandle<()>>,
    thread_comm: ZSock,
}

impl Drop for ZapHandler {
    fn drop(&mut self) {
        // Ignore failure as it means the thread has already
        // terminated.
        let _ = self.thread_comm.send_str(THREAD_TERM);
        if let Some(h) = self.worker.take() {
            h.join().unwrap();
        }
    }
}

impl ZapHandler {
    // Seperate new() and run_worker() to allow for mocking sockets
    pub fn new(cert_type: Option<CertType>, cert: &ZCert, auth_cert: &ZCert, auth_server: &str, auth_port: u32, allow_self: bool) -> Result<ZapHandler> {
        let zap = try!(ZSock::new_rep(ZAP_ENDPOINT));
        zap.set_linger(0);

        let mut subscriber = ZSock::new(SocketType::SUB);
        subscriber.set_curve_serverkey(auth_cert.public_txt());
        cert.apply(&mut subscriber);
        subscriber.set_linger(0);
        try!(subscriber.connect(&format!("tcp://{}:{}", auth_server, auth_port)));
        match cert_type {
            Some(ct) => subscriber.set_subscribe(ct.to_str()),
            None => subscriber.set_subscribe(""),
        }

        let seed = if allow_self {
            // Copy cert to new owned cert
            let c = ZCert::from_keys(cert.public_key(), cert.secret_key());
            c.set_meta("name", &cert.meta("name").unwrap().unwrap());
            c.set_meta("type", &cert.meta("type").unwrap().unwrap());
            Some(vec![try!(Cert::from_zcert(c))])
        } else {
            None
        };
        let cache = CertCache::new(seed);

        Self::run_worker(zap, subscriber, cache)
    }

    fn run_worker(zap: ZSock, subscriber: ZSock, cache: CertCache) -> Result<ZapHandler> {
        let (comm, comm_child) = try!(ZSys::create_pipe());
        comm.set_linger(0);
        comm_child.set_linger(0);

        Ok(ZapHandler {
            worker: Some(spawn(move || {
                let mut w = Worker::new(zap, subscriber, comm_child, cache);
                if let Err(_e) = w.run() {
                    error!("ZAP Error: {:?}", _e);
                    // XXX impl error_handler()
                }
            })),
            thread_comm: comm,
        })
    }
}

struct Worker {
    zap: ZSock,
    subscriber: ZSock,
    comm: ZSock,
    cache: CertCache,
}

impl Worker {
    fn new(zap: ZSock, subscriber: ZSock, comm: ZSock, cache: CertCache) -> Worker {
        Worker {
            zap: zap,
            subscriber: subscriber,
            comm: comm,
            cache: cache,
        }
    }

    fn run(&mut self) -> Result<()> {
        let mut poller = try!(ZPoller::new());
        try!(poller.add(&mut self.zap));
        try!(poller.add(&mut self.subscriber));
        try!(poller.add(&mut self.comm));

        loop {
            let sock: Option<ZSock> = poller.wait(None);
            if let Some(mut sock) = sock {
                if sock == self.zap {
                    // These frames are system defined. We can safely
                    // unwrap them.
                    let msg = ZMsg::expect_recv(&mut sock, 7, Some(7), false).unwrap();
                    let mut request = try!(ZapRequest::new(
                        &self.cache,
                        &mut self.zap,
                        msg.popstr().unwrap().unwrap(),
                        msg.popstr().unwrap().unwrap(),
                        msg.popstr().unwrap().unwrap(),
                        msg.popstr().unwrap().unwrap(),
                        msg.popstr().unwrap().unwrap(),
                        msg.popstr().unwrap().unwrap(),
                        try!(z85_encode(&try!(msg.popbytes()).unwrap()))));

                    try!(request.authenticate());
                }
                else if sock == self.subscriber {
                    try!(self.cache.recv(&mut sock));
                }
                else if sock == self.comm && try!(self.comm.recv_str()).unwrap_or(String::new()) == THREAD_TERM {
                    break;
                }
            }

            if poller.expired() {
                return Err(Error::PollerTimeout);
            }
            else if poller.terminated() {
                break;
            }
        }

        Ok(())
    }
}

struct ZapRequest<'a> {
    cache: &'a CertCache,
    zap: &'a mut ZSock,
    _version: String,
    sequence: String,
    _domain: String,
    _address: String,
    _identity: String,
    mechanism: String,
    client_pk: String,
}

impl<'a> ZapRequest<'a> {
    fn new(cache: &'a CertCache,
           zap: &'a mut ZSock,
           version: String,
           sequence: String,
           domain: String,
           address: String,
           identity: String,
           mechanism: String,
           client_pk: String) -> Result<ZapRequest<'a>> {

        // This is hardcoded in ZMQ, so must always be
        // consistent, or we won't stick around.
        if version != "1.0" {
            return Err(Error::ZapVersion);
        }

        // Ensure that client key is valid
        if client_pk.len() != 40 {
            return Err(Error::InvalidZapRequest);
        }

        debug!("New ZAP request from {} ({}) via {}", client_pk, address, mechanism);

        Ok(ZapRequest {
            cache: cache,
            zap: zap,
            _version: version,
            sequence: sequence,
            _domain: domain,
            _address: address,
            _identity: identity,
            mechanism: mechanism,
            client_pk: client_pk,
        })
    }

    fn authenticate(&mut self) -> Result<()> {
        match self.mechanism.as_ref() {
            "CURVE" => {
                let cert = self.cache.get(&self.client_pk);
                if let Some(c) = cert {
                    debug!("Authenticated {}", self.client_pk);
                    try!(self.zap_reply(true, Some(c.encode_meta())));
                    return Ok(());
                }
            },
            _ => (),
        }

        debug!("Could not authenticate {}", self.client_pk);
        try!(self.zap_reply(false, None));
        Ok(())
    }

    fn zap_reply(&mut self, ok: bool, metadata: Option<Vec<u8>>) -> Result<()> {
        let msg = ZMsg::new();
        try!(msg.addstr("1.0"));
        try!(msg.addstr(&self.sequence));

        if ok {
            try!(msg.addstr("200"));
            try!(msg.addstr("OK"));
        } else {
            try!(msg.addstr("400"));
            try!(msg.addstr("No access"));
        }

        try!(msg.addstr("")); // User ID
        match metadata {
            Some(data) => {
                let frame = try!(ZFrame::new(&data));
                try!(msg.append(frame));
            }
            None => try!(msg.addstr("")),
        }

        try!(msg.send(self.zap));
        Ok(())
    }
}

impl<'a> fmt::Debug for ZapRequest<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ZapRequest {{ version: {}, sequence: {}, domain: {}, address: {}, identity: {}, mechanism: {}, client_pk: {} }}",
            self._version,
            self.sequence,
            self._domain,
            self._address,
            self._identity,
            self.mechanism,
            self.client_pk)
    }
}

#[cfg(test)]
mod tests {
    use cert::{Cert, CertType};
    use cert_cache::CertCache;
    use czmq::{ZCert, ZMsg, ZSock, SocketType, ZSys};
    use std::thread::sleep;
    use std::time::Duration;
    use super::*;

    #[test]
    fn test_auth() {
        ZSys::init();

        let cert = Cert::new("jimbob", CertType::User).unwrap();

        let mut zap = ZSock::new_req("inproc://zap_handler_test_zap").unwrap();
        zap.set_sndtimeo(Some(500));
        zap.set_rcvtimeo(Some(500));

        let zap_server = ZSock::new_rep("inproc://zap_handler_test_zap").unwrap();

        let mut publisher = ZSock::new_pub("inproc://zap_handler_test_pub").unwrap();
        publisher.set_sndtimeo(Some(500));

        let subscriber = ZSock::new(SocketType::SUB);
        subscriber.set_subscribe(CertType::User.to_str());
        subscriber.connect("inproc://zap_handler_test_pub").unwrap();

        let _handler = ZapHandler::run_worker(zap_server, subscriber, CertCache::new(None)).unwrap();

        let zap_msg = new_zap_msg(&cert);
        zap_msg.send(&mut zap).unwrap();

        let reply = ZMsg::recv(&mut zap).unwrap();
        reply.popstr().unwrap().unwrap();
        reply.popstr().unwrap().unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "400");
        assert_eq!(reply.popstr().unwrap().unwrap(), "No access");

        let publish_msg = ZMsg::new();
        publish_msg.addstr("user").unwrap();
        publish_msg.addstr("ADD").unwrap();
        publish_msg.addstr(cert.public_txt()).unwrap();
        publish_msg.addbytes(&cert.encode_meta()).unwrap();
        publish_msg.send(&mut publisher).unwrap();

        sleep(Duration::from_millis(200));

        let zap_msg = new_zap_msg(&cert);
        zap_msg.send(&mut zap).unwrap();
        let reply = ZMsg::recv(&mut zap).unwrap();
        reply.popstr().unwrap().unwrap();
        reply.popstr().unwrap().unwrap();
        assert_eq!(reply.popstr().unwrap().unwrap(), "200");
        assert_eq!(reply.popstr().unwrap().unwrap(), "OK");
    }

    fn new_zap_msg(cert: &ZCert) -> ZMsg {
        let zap_msg = ZMsg::new();
        zap_msg.addstr("1.0").unwrap();
        zap_msg.addstr("1").unwrap();
        zap_msg.addstr("test-domain").unwrap();
        zap_msg.addstr("127.0.0.1").unwrap();
        zap_msg.addstr("").unwrap();
        zap_msg.addstr("CURVE").unwrap();
        zap_msg.addbytes(cert.public_key()).unwrap();
        zap_msg
    }
}
