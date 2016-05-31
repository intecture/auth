// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use czmq::{ZMsg, ZSock};
use error::{Error, Result};
use std::error::Error as StdError;

pub trait ZMsgExtended {
    fn expect_recv(sock: &ZSock, min: usize, max: Option<usize>, block: bool) -> Result<ZMsg>;
    fn new_err(err: &Error) -> Result<ZMsg>;
    fn new_ok() -> Result<ZMsg>;
    fn send_multi(sock: &ZSock, frames: &[&str]) -> Result<()>;
}

impl ZMsgExtended for ZMsg {
    /// Receive a variable number of args from sock. We expect the number
    /// of args from `sock` to be between `min` and `max`.
    /// If max = None then we allow a variable number of args.
    fn expect_recv(sock: &ZSock, min: usize, max: Option<usize>, block: bool) -> Result<ZMsg> {
        let zmsg = if block {
            try!(ZMsg::recv(sock))
        } else {
            let rcvtimeo = sock.rcvtimeo();
            sock.set_rcvtimeo(Some(0));
            let result = ZMsg::recv(sock);
            sock.set_rcvtimeo(rcvtimeo);
            result.unwrap_or(ZMsg::new())
        };

        if min > zmsg.size() || (max.is_some() && max.unwrap() < zmsg.size()) {
            Err(Error::InvalidArgsCount)
        } else {
            Ok(zmsg)
        }
    }

    fn new_err(err: &Error) -> Result<ZMsg> {
        let zmsg = ZMsg::new();
        try!(zmsg.addstr("Err"));
        try!(zmsg.addstr(err.description()));
        Ok(zmsg)
    }

    fn new_ok() -> Result<ZMsg> {
        let zmsg = ZMsg::new();
        try!(zmsg.addstr("Ok"));
        Ok(zmsg)
    }

    fn send_multi(sock: &ZSock, frames: &[&str]) -> Result<()> {
        let zmsg = ZMsg::new();

        for frame in frames {
            try!(zmsg.addstr(frame));
        }

        try!(zmsg.send(sock));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use czmq::{ZMsg, ZSock, zsys_init};
    use error::Error;
    use super::*;

    /// Test providing 1 and only 1 arg
    #[test]
    fn test_recv_args_ok_eq() {
        zsys_init();

        let server = ZSock::new_rep("inproc://msg_recv_args_ok_eq").unwrap();
        let client = ZSock::new_req("inproc://msg_recv_args_ok_eq").unwrap();

        let msg = ZMsg::new();
        msg.addstr("0").unwrap();
        msg.send(&client).unwrap();

        let rcv_msg = ZMsg::expect_recv(&server, 1, Some(1), true).unwrap();
        assert_eq!(rcv_msg.popstr().unwrap().unwrap(), "0");
    }

    /// Test providing 1 or more args
    #[test]
    fn test_recv_args_ok_range() {
        zsys_init();

        let server = ZSock::new_rep("inproc://msg_recv_args_ok_range").unwrap();
        let client = ZSock::new_req("inproc://msg_recv_args_ok_range").unwrap();

        let msg = ZMsg::new();
        msg.addstr("0").unwrap();
        msg.send(&client).unwrap();

        let rcv_msg = ZMsg::expect_recv(&server, 1, Some(2), true).unwrap();
        assert_eq!(rcv_msg.popstr().unwrap().unwrap(), "0");
    }

    /// Test providing 1+ args
    #[test]
    fn test_recv_args_ok_variable() {
        zsys_init();

        let server = ZSock::new_rep("inproc://msg_recv_args_ok_variable").unwrap();
        let client = ZSock::new_req("inproc://msg_recv_args_ok_variable").unwrap();

        let msg = ZMsg::new();
        msg.addstr("0").unwrap();
        msg.addstr("1").unwrap();
        msg.addstr("2").unwrap();
        msg.send(&client).unwrap();

        let rcv_msg = ZMsg::expect_recv(&server, 2, None, true).unwrap();
        assert_eq!(rcv_msg.popstr().unwrap().unwrap(), "0");
        assert_eq!(rcv_msg.popstr().unwrap().unwrap(), "1");
        assert_eq!(rcv_msg.popstr().unwrap().unwrap(), "2");
    }

    /// Test failing less than 3 args
    #[test]
    fn test_recv_args_err_min() {
        zsys_init();

        let server = ZSock::new_rep("inproc://msg_recv_args_err_min").unwrap();
        let client = ZSock::new_req("inproc://msg_recv_args_err_min").unwrap();

        let msg = ZMsg::new();
        msg.addstr("0").unwrap();
        msg.addstr("1").unwrap();
        msg.send(&client).unwrap();

        let rcv_msg = ZMsg::expect_recv(&server, 3, None, true);
        assert!(rcv_msg.is_err());
    }

    /// Test failing more than 1 arg
    #[test]
    fn test_recv_args_err_max() {
        zsys_init();

        let server = ZSock::new_rep("inproc://msg_recv_args_err_max").unwrap();
        let client = ZSock::new_req("inproc://msg_recv_args_err_max").unwrap();

        let msg = ZMsg::new();
        msg.addstr("0").unwrap();
        msg.addstr("1").unwrap();
        msg.addstr("2").unwrap();
        msg.send(&client).unwrap();

        let rcv_msg = ZMsg::expect_recv(&server, 0, Some(1), true);
        assert!(rcv_msg.is_err());
    }

    #[test]
    fn test_new_err() {
        assert!(ZMsg::new_err(&Error::InvalidArgsCount).is_ok());
    }

    #[test]
    fn test_new_ok() {
        assert!(ZMsg::new_ok().is_ok());
    }

    #[test]
    fn test_send_multi() {
        let client = ZSock::new_push("inproc://msg_send_multi").unwrap();
        let server = ZSock::new_pull("inproc://msg_send_multi").unwrap();

        ZMsg::send_multi(&client, &["0", "1", "2"]).unwrap();

        let rcv = ZMsg::recv(&server).unwrap();
        assert_eq!(rcv.popstr().unwrap().unwrap(), "0");
        assert_eq!(rcv.popstr().unwrap().unwrap(), "1");
        assert_eq!(rcv.popstr().unwrap().unwrap(), "2");
    }
}
