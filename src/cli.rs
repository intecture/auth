// Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

extern crate czmq;
extern crate docopt;
extern crate rustc_serialize;
#[cfg(test)]
extern crate tempdir;
extern crate zdaemon;

mod cert;
mod config;
mod error;

use cert::{Cert, CertType};
use config::Config;
use docopt::Docopt;
use error::{Error, Result};
use std::fmt::{Debug, Display};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::result::Result as StdResult;
use zdaemon::ConfigFile;

static USAGE: &'static str = "
Intecture Auth.

Usage:
  inauth_cli user add [(-s | --silent)] <username>

  Options:
    -s --silent     Save private key instead of printing it.
";

#[derive(Debug, RustcDecodable)]
struct Args {
    cmd_add: bool,
    cmd_user: bool,
    arg_username: String,
    flag_s: bool,
    flag_silent: bool,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    if args.cmd_user && args.cmd_add {
        let config = try_exit(load_conf("auth.json", &["/usr/local/etc", "/etc"]));
        let cert = try_exit(Cert::new(&args.arg_username, CertType::User));
        try_exit(cert.save_public(&format!("{}/{}.crt", &config.cert_path, &args.arg_username)));

        if args.flag_s || args.flag_silent {
            try_exit(cert.save_secret(&format!("{}.crt", &args.arg_username)));
        } else {
            println!("Please distribute this certificate securely.

------------------------COPY BELOW THIS LINE-------------------------
{}
------------------------COPY ABOVE THIS LINE-------------------------", cert.secret_txt());
        }
    }
}

fn load_conf<P: AsRef<Path>>(path: P, default_paths: &[&str]) -> Result<Config> {
    if path.as_ref().is_relative() {
        for p in default_paths.iter() {
            let mut pathbuf = PathBuf::from(p);
            pathbuf.push("intecture");
            pathbuf.push(&path);

            match ConfigFile::load(&pathbuf) {
                Ok(conf) => return Ok(conf),
                Err(_) => continue,
            }
        }

        Err(Error::MissingConf)
    } else {
        Ok(try!(Config::load(&path.as_ref())))
    }
}

fn try_exit<T, E>(r: StdResult<T, E>) -> T
    where E: Into<Error> + Debug + Display {
    if let Err(e) = r {
        println!("{:?}", e);
        exit(1);
    }

    r.unwrap()
}

#[cfg(test)]
mod tests {
    use config::Config;
    use std::fs::create_dir;
    use std::path::PathBuf;
    use super::load_conf;
    use tempdir::TempDir;
    use zdaemon::ConfigFile;

    #[test]
    fn test_load_conf() {
        let dir = TempDir::new("service_test_load_conf").unwrap();
        let dir_path = dir.path().to_str().unwrap();

        let config = Config {
            server_cert: "/path".into(),
            cert_path: "/path".into(),
            api_port: 123,
            update_port: 123,
        };

        // Relative path
        let pathstr = format!("{}/intecture", dir_path);
        let mut path = PathBuf::from(pathstr);
        create_dir(&path).unwrap();
        path.push("test_config.json");
        config.save(&path).unwrap();
        let c = load_conf("test_config.json", &[dir_path]).unwrap();
        assert_eq!(c.api_port, 123);

        // Relative nested path
        let pathstr = format!("{}/intecture/nested", dir_path);
        let mut path = PathBuf::from(pathstr);
        create_dir(&path).unwrap();
        path.push("test_config.json");
        config.save(&path).unwrap();
        let c = load_conf("nested/test_config.json", &[dir_path]).unwrap();
        assert_eq!(c.api_port, 123);

        // Absolute path
        let c = load_conf(&format!("{}/intecture/test_config.json", dir_path), &["/fake/path"]).unwrap();
        assert_eq!(c.api_port, 123);
    }
}
