// Copyright 2015-2017 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

use cert::Cert;
use czmq::ZCert;
use error::{Error, Result};
use std::collections::HashMap;
use std::fs::{metadata, read_dir, remove_file};
use super::PersistenceAdaptor;

pub struct PersistDisk {
    path: String,
    name_cache: HashMap<String, String>,
}

impl PersistDisk {
    pub fn new(path: &str) -> Result<PersistDisk> {
        // Check that path exists
        let meta = try!(metadata(path));
        if !meta.is_dir() {
            return Err(Error::InvalidCertPath);
        }

        let mut me = PersistDisk {
            path: path.to_string(),
            name_cache: HashMap::new(),
        };

        // Warm up name cache
        try!(me.dump());

        Ok(me)
    }

    fn pubkey_to_name(&self, pubkey: &str) -> Option<String> {
        for (n, pk) in &self.name_cache {
            if pubkey == pk {
                return Some(n.to_string());
            }
        }

        None
    }
}

impl PersistenceAdaptor for PersistDisk {
    type PK = String;

    fn create(&mut self, cert: &Cert) -> Result<String> {
        if self.name_cache.contains_key(cert.name()) {
            return Err(Error::CertNameCollision);
        }

        let cert_path = format!("{}/{}.crt", &self.path, &cert.name());

        // Replace with own cert template
        try!(cert.save_public(&cert_path));

        self.name_cache.insert(cert.name().to_string(), cert.public_txt().to_string());

        Ok(cert_path)
    }

    fn read(&mut self, name: &str) -> Result<Cert> {
        let cert_path = format!("{}/{}.crt", &self.path, name);

        // XXX Replace with own cert template
        let cert = try!(Cert::from_zcert(try!(ZCert::load(&cert_path))));

        self.name_cache.insert(cert.name().to_string(), cert.public_txt().to_string());

        Ok(cert)
    }

    fn read_pubkey(&mut self, pubkey: &str) -> Result<Cert> {
        match self.pubkey_to_name(pubkey) {
            Some(name) => {
                self.read(&name)
            },
            None => Err(Error::InvalidCert),
        }
    }

    fn delete(&mut self, name: &str) -> Result<()> {
        try!(remove_file(&format!("{}/{}.crt", &self.path, name)));
        self.name_cache.remove(name);
        Ok(())
    }

    fn delete_pubkey(&mut self, pubkey: &str) -> Result<()> {
        match self.pubkey_to_name(pubkey) {
            Some(name) => {
                try!(self.delete(&name));
                Ok(())
            },
            None => Err(Error::InvalidCert),
        }
    }

    fn dump(&mut self) -> Result<Vec<Cert>> {
        let mut certs = Vec::new();

        for node in try!(read_dir(&self.path)) {
            let node = try!(node);

            if try!(node.file_type()).is_file() {
                let file_name = match node.file_name().to_str() {
                    Some(name) => name.to_string(),
                    None => return Err(Error::InvalidCertPath),
                };

                if file_name.ends_with(".crt") {
                    let (name, _) = file_name.split_at(file_name.len() - 4);
                    certs.push(try!(self.read(name)));
                }
            }
        }

        Ok(certs)
    }
}

#[cfg(test)]
mod tests {
    use cert::{Cert, CertType};
    use std::collections::HashMap;
    use std::fs::metadata;
    use storage::PersistenceAdaptor;
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_new() {
        let dir = TempDir::new("storage_disk_new").unwrap();

        let disk = PersistDisk::new("fake/path");
        assert!(disk.is_err());

        let disk = PersistDisk::new(dir.path().to_str().unwrap());
        assert!(disk.is_ok());
    }

    #[test]
    fn test_pubkey_to_name() {
        let mut cache = HashMap::new();
        cache.insert("name".to_string(), "pubkey".to_string());

        let disk = PersistDisk {
            path: "/path/to/store".to_string(),
            name_cache: cache,
        };

        assert!(disk.pubkey_to_name("nonexistent").is_none());
        assert_eq!(disk.pubkey_to_name("pubkey").unwrap(), "name");
    }

    #[test]
    fn test_create() {
        let dir = TempDir::new("storage_disk_create").unwrap();

        let cert = Cert::new("test_user", CertType::User).unwrap();
        let mut disk = PersistDisk::new(dir.path().to_str().unwrap()).unwrap();

        let path = disk.create(&cert).unwrap();
        assert!(metadata(&path).is_ok());

        assert!(disk.create(&cert).is_err());
    }

    #[test]
    fn test_delete() {
        let dir = TempDir::new("storage_disk_delete").unwrap();

        let cert = Cert::new("test_user", CertType::User).unwrap();
        let mut disk = PersistDisk::new(dir.path().to_str().unwrap()).unwrap();

        assert!(disk.delete("fakepk").is_err());

        disk.create(&cert).unwrap();
        assert!(disk.delete("test_user").is_ok());
    }

    #[test]
    fn test_dump() {
        let dir = TempDir::new("storage_disk_dump").unwrap();
        let mut disk = PersistDisk::new(dir.path().to_str().unwrap()).unwrap();

        let c1 = Cert::new("mr", CertType::User).unwrap();
        disk.create(&c1).unwrap();
        let c2 = Cert::new("plow", CertType::User).unwrap();
        disk.create(&c2).unwrap();

        let mut certs = disk.dump().unwrap();
        let dump_c1 = certs.pop().unwrap();
        let dump_c2 = certs.pop().unwrap();

        // We don't know what order they will be in, so test either
        // sequence. We also can't test for equality as the cert
        // pointers are different.
        assert!((c1.public_txt() == dump_c1.public_txt() && c2.public_txt() == dump_c2.public_txt()) ||
                (c1.public_txt() == dump_c2.public_txt() && c2.public_txt() == dump_c1.public_txt()));
    }
}
