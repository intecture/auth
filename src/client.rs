// Copyright 2015-2017 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

extern crate czmq;
extern crate zmq;

// XXX These crates are only required for error module to compile. In
// the future these dependencies should be removed.
extern crate rustc_serialize;
extern crate zdaemon;

#[allow(dead_code)]
mod cert;
#[allow(dead_code)]
mod cert_cache;
#[allow(dead_code)]
mod error;
mod zap_handler;

pub use cert::CertType;
pub use zap_handler::ZapHandler;

use error::Error;
use std::convert;

// Only client.rs uses zmq crate, so our ZMQ error handlers have to
// go here.
impl convert::From<zmq::EncodeError> for Error {
    fn from(e: zmq::EncodeError) -> Error {
        Error::ZmqEncode(format!("{}", e))
    }
}
