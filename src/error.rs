// Copyright 2015-2017 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use czmq;
use rustc_serialize::json;
use std::{convert, error, fmt, io, result};
use zdaemon;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    CertNameCollision,
    Czmq(czmq::Error),
    Forbidden,
    InvalidArg,
    InvalidArgsCount,
    InvalidCert,
    InvalidCertFeed,
    InvalidCertMeta,
    InvalidCertPath,
    InvalidEndpoint,
    InvalidZapRequest,
    Io(io::Error),
    JsonEncoder(json::EncoderError),
    MissingConf,
    PollerTimeout,
    ZapVersion,
    ZDaemon(zdaemon::Error),
    ZmqEncode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CertNameCollision => write!(f, "Certificate name already exists"),
            Error::Czmq(ref e) => write!(f, "CZMQ error: {}", e),
            Error::Forbidden => write!(f, "Access to this endpoint is forbidden"),
            Error::InvalidArg => write!(f, "Invalid argument provided"),
            Error::InvalidArgsCount => write!(f, "Invalid number of args provided"),
            Error::InvalidCert => write!(f, "Invalid certificate"),
            Error::InvalidCertFeed => write!(f, "Invalid message from certificate feed"),
            Error::InvalidCertMeta => write!(f, "Invalid certificate metadata"),
            Error::InvalidCertPath => write!(f, "Invalid certificate path"),
            Error::InvalidEndpoint => write!(f, "Invalid endpoint"),
            Error::InvalidZapRequest => write!(f, "Invalid ZAP request"),
            Error::Io(ref e) => write!(f, "IO error: {}", e),
            Error::JsonEncoder(ref e) => write!(f, "JSON encoder error: {}", e),
            Error::MissingConf => write!(f, "Cannot open Agent config"),
            Error::PollerTimeout => write!(f, "Timeout while polling sockets"),
            Error::ZapVersion => write!(f, "ZAP version is invalid"),
            Error::ZDaemon(ref e) => write!(f, "ZDaemon error: {}", e),
            Error::ZmqEncode(ref e) => write!(f, "Could not encode Z85 string: {}", e),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::CertNameCollision => "Certificate name already exists",
            Error::Czmq(ref e) => e.description(),
            Error::Forbidden => "Access to this endpoint is forbidden",
            Error::InvalidArg => "Invalid argument provided",
            Error::InvalidArgsCount => "Invalid number of args provided",
            Error::InvalidCert => "Invalid certificate",
            Error::InvalidCertFeed => "Invalid message from certificate feed",
            Error::InvalidCertMeta => "Invalid certificate metadata",
            Error::InvalidCertPath => "Invalid certificate path",
            Error::InvalidEndpoint => "Invalid endpoint",
            Error::InvalidZapRequest => "Invalid ZAP request",
            Error::Io(ref e) => e.description(),
            Error::JsonEncoder(ref e) => e.description(),
            Error::MissingConf => "Cannot open config",
            Error::PollerTimeout => "Timeout while polling sockets",
            Error::ZapVersion => "ZAP version is invalid",
            Error::ZDaemon(ref e) => e.description(),
            Error::ZmqEncode(_) => "Could not encode Z85 string",
        }
    }
}

impl convert::From<czmq::Error> for Error {
    fn from(err: czmq::Error) -> Error {
        Error::Czmq(err)
    }
}

impl convert::From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl convert::From<json::EncoderError> for Error {
    fn from(err: json::EncoderError) -> Error {
        Error::JsonEncoder(err)
    }
}

impl convert::From<zdaemon::Error> for Error {
    fn from(err: zdaemon::Error) -> Error {
        Error::ZDaemon(err)
    }
}

impl convert::From<Error> for zdaemon::Error {
    fn from(err: Error) -> zdaemon::Error {
        zdaemon::Error::Generic(Box::new(err))
    }
}
