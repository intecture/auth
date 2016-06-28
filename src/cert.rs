// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use czmq::ZCert;
use error::{Error, Result};
use std::ops::{Deref, DerefMut};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CertType {
    Host,
    // Runtime,
    User,
}

impl CertType {
    pub fn from_str(ctype: &str) -> Result<CertType> {
        match ctype {
            "host" => Ok(CertType::Host),
            // "runtime" => Ok(CertType::Runtime),
            "user" => Ok(CertType::User),
            _ => Err(Error::InvalidCertMeta)
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            &CertType::Host => "host",
            // &CertType::Runtime => "runtime",
            &CertType::User => "user",
        }
    }
}

#[derive(Debug)]
pub struct Cert {
    zcert: ZCert,
    name: String,
    cert_type: CertType,
}

impl Cert {
    pub fn new(name: &str, cert_type: CertType) -> Result<Cert> {
        let zcert = try!(ZCert::new());
        zcert.set_meta("name", name);
        zcert.set_meta("type", cert_type.to_str());

        Ok(Cert {
            zcert: zcert,
            name: name.to_string(),
            cert_type: cert_type,
        })
    }

    pub fn from_zcert(zcert: ZCert) -> Result<Cert> {
        let name = if let Some(Ok(n)) = zcert.meta("name") {
            n
        } else {
            return Err(Error::InvalidCert);
        };

        let cert_type = if let Some(Ok(t)) = zcert.meta("type") {
            try!(CertType::from_str(&t))
        } else {
            return Err(Error::InvalidCert);
        };

        Ok(Cert {
            zcert: zcert,
            name: name,
            cert_type: cert_type,
        })
    }

    #[allow(dead_code)]
    pub fn cert_type(&self) -> CertType {
        self.cert_type
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Deref for Cert {
    type Target = ZCert;

    fn deref(&self) -> &ZCert {
        &self.zcert
    }
}

impl DerefMut for Cert {
    fn deref_mut(&mut self) -> &mut ZCert {
        &mut self.zcert
    }
}

impl PartialEq for Cert {
    fn eq(&self, other: &Cert) -> bool {
        ZCert::eq(&self.zcert, &other.zcert)
    }
}

#[cfg(test)]
mod tests {
    use czmq::ZCert;
    use super::*;

    #[test]
    fn test_convert_cert_type() {
        assert!(CertType::from_str("moo").is_err());
        assert_eq!(CertType::from_str("host").unwrap(), CertType::Host);
        assert_eq!(CertType::User.to_str(), "user");
    }

    #[test]
    fn test_new() {
        assert!(Cert::new("test_user", CertType::User).is_ok());
    }

    #[test]
    fn test_from_zcert() {
        let zcert = ZCert::new().unwrap();
        assert!(Cert::from_zcert(zcert).is_err());

        let zcert = ZCert::new().unwrap();
        zcert.set_meta("name", "test_cert");
        zcert.set_meta("type", "host");
        assert!(Cert::from_zcert(zcert).is_ok());
    }
}
