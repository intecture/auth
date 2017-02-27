// Copyright 2015-2017 Intecture Developers. See the COPYRIGHT file at the
// top-level directory of this distribution and at
// https://intecture.io/COPYRIGHT.
//
// Licensed under the Mozilla Public License 2.0 <LICENSE or
// https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
// modified, or distributed except according to those terms.

extern crate czmq;
extern crate docopt;
extern crate rustc_serialize;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[cfg(test)]
extern crate tempdir;
extern crate zdaemon;
extern crate zmq;

mod cert;
mod config;
mod error;

use cert::{Cert, CertType};
use config::Config;
use docopt::Docopt;
use error::{Error, Result};
use std::{env, fs};
use std::io::Read;
use std::fmt::{Debug, Display};
use std::path::Path;
use std::process::exit;
use std::result::Result as StdResult;

static USAGE: &'static str = "
Intecture Auth CLI.

Usage:
  inauth_cli user add [(-s | --silent)] [(-c <path> | --config <path>)] <username>
  inauth_cli --version

  Options:
    -c --config <path>  Path to auth.json, e.g. \"/usr/local/etc\"
    -s --silent         Save private key instead of printing it.
    --version           Print this script's version.
";

#[derive(Debug, RustcDecodable)]
struct Args {
    cmd_add: bool,
    cmd_user: bool,
    arg_username: String,
    flag_c: Option<String>,
    flag_config: Option<String>,
    flag_s: bool,
    flag_silent: bool,
    flag_version: bool,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!(env!("CARGO_PKG_VERSION"));
        exit(0);
    }
    else if args.cmd_user && args.cmd_add {
        let config_path = if args.flag_c.is_some() { args.flag_c.as_ref() } else { args.flag_config.as_ref() };
        let config = try_exit(read_conf(config_path));
        let cert = try_exit(Cert::new(&args.arg_username, CertType::User));
        try_exit(cert.save_public(&format!("{}/{}.crt", &config.cert_path, &args.arg_username)));

        if args.flag_s || args.flag_silent {
            try_exit(cert.save_secret(&format!("{}.crt", &args.arg_username)));
        } else {
            println!("**********
* PLEASE NOTE: You must restart the Auth server before this certificate will become valid!
**********

Please distribute this certificate securely.

------------------------COPY BELOW THIS LINE-------------------------
metadata
    name = \"{}\"
    type = \"user\"
curve
    public-key = \"{}\"
    secret-key = \"{}\"
------------------------COPY ABOVE THIS LINE-------------------------", args.arg_username, cert.public_txt(), cert.secret_txt());
        }
    }
}

fn read_conf<P: AsRef<Path>>(path: Option<P>) -> Result<Config> {
    if let Some(p) = path {
        do_read_conf(p)
    }
    else if let Ok(p) = env::var("INAUTH_CONFIG_DIR") {
        do_read_conf(p)
    }
    else if let Ok(c) = do_read_conf("/usr/local/etc/intecture") {
        Ok(c)
    } else {
        do_read_conf("/etc/intecture")
    }
}

fn do_read_conf<P: AsRef<Path>>(path: P) -> Result<Config> {
    let mut path = path.as_ref().to_owned();
    path.push("auth.json");

    let mut fh = fs::File::open(&path)?;
    let mut json = String::new();
    fh.read_to_string(&mut json)?;
    Ok(serde_json::from_str(&json)?)
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
    use std::{env, fs};
    use std::io::Write;
    use super::read_conf;
    use tempdir::TempDir;

    #[test]
    fn test_read_conf() {
        let tmpdir = TempDir::new("cli_test_read_conf").unwrap();
        let mut path = tmpdir.path().to_owned();

        path.push("auth.json");
        let mut fh = fs::File::create(&path).unwrap();
        fh.write_all(b"{\"server_cert\": \"/path\", \"cert_path\": \"/path\", \"api_port\": 123, \"update_port\": 123}").unwrap();
        path.pop();

        assert!(read_conf(Some(&path)).is_ok());
        env::set_var("INAUTH_CONFIG_DIR", path.to_str().unwrap());
        let none: Option<String> = None;
        assert!(read_conf(none).is_ok());
    }
}
