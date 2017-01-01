// Copyright 2015-2017 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

mod disk;

pub use self::disk::PersistDisk;

use cert::Cert;
use error::Result;

pub trait PersistenceAdaptor {
    type PK;

    fn create(&mut self, cert: &Cert) -> Result<Self::PK>;
    fn read(&mut self, name: &str) -> Result<Cert>;
    fn read_pubkey(&mut self, pubkey: &str) -> Result<Cert>;
    fn delete(&mut self, name: &str) -> Result<()>;
    fn delete_pubkey(&mut self, pubkey: &str) -> Result<()>;
    fn dump(&mut self) -> Result<Vec<Cert>>;
}
