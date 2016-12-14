#!/bin/sh
# Copyright 2015-2016 Intecture Developers. See the COPYRIGHT file at the
# top-level directory of this distribution and at
# https://intecture.io/COPYRIGHT.
#
# Licensed under the Mozilla Public License 2.0 <LICENSE or
# https://www.tldrlegal.com/l/mpl-2.0>. This file may not be copied,
# modified, or distributed except according to those terms.

# Undefined vars are errors
set -u

# Globals
prefix=""
libdir=""
libext=""
sysconfdir=""
os="$(uname -s)"
make="make"

case "$os" in
    Linux)
        prefix="/usr"
        sysconfdir="/etc"
        libext="so"

        # When we can statically link successfully, we should be able
        # to produce vendor-agnostic packages.
        if [ -f "/etc/centos-release" ]; then
            os="centos"
            libdir="$prefix/lib64"
        elif [ -f "/etc/fedora-release" ]; then
            os="fedora"
            libdir="$prefix/lib64"
        elif [ -f "/etc/lsb-release" ]; then
            os="ubuntu"
            libdir="$prefix/lib"
        elif [ -f "/etc/debian_version" ]; then
            os="debian"
            libdir="$prefix/lib"
        else
            echo "unsupported Linux flavour" >&2
            exit 1
        fi
        ;;

    FreeBSD)
        os="freebsd"
        prefix="/usr/local"
		libdir="$prefix/lib"
        libext="so"
        sysconfdir="$prefix/etc"
        make="gmake"
        ;;

    Darwin)
        os="darwin"
        prefix="/usr/local"
		libdir="$prefix/lib"
        libext="dylib"
        sysconfdir="$prefix/etc"
        ;;

    *)
        echo "unrecognized OS type: $os" >&2
        exit 1
        ;;
esac

main() {
    local _cargodir=$(pwd)
    local _tmpdir="$(mktemp -d 2>/dev/null || mktemp -d -t intecture)"
    cd "$_tmpdir"

    # ZeroMQ dependency
    if ! $(pkg-config --exists libzmq) || [ $(pkg-config libzmq --modversion) != "4.2.0" ]; then
        curl -sSOL https://github.com/zeromq/libzmq/releases/download/v4.2.0/zeromq-4.2.0.tar.gz
        tar zxf zeromq-4.2.0.tar.gz
        cd zeromq-4.2.0
        ./autogen.sh
        ./configure --prefix=$prefix --libdir=$libdir
        $make
        $make install
        cd ..
    fi

    # CZMQ dependency
    if ! $(pkg-config --exists libczmq) || [ $(pkg-config libczmq --modversion) != "4.0.1" ]; then
        curl -sSOL https://github.com/zeromq/czmq/releases/download/v4.0.1/czmq-4.0.1.tar.gz
        tar zxf czmq-4.0.1.tar.gz
        cd czmq-4.0.1
        ./configure --prefix=$prefix --libdir=$libdir
        $make
        $make install
        cd ..
    fi

    # Build and install project assets
    cargo build --release --manifest-path "$_cargodir/Cargo.toml"

    local _version=$($_cargodir/target/release/inauth_cli --version)
    local _pkgdir="inauth-$_version"

    # Create package dir structure
    mkdir "$_pkgdir"
    mkdir "$_pkgdir/include"
    mkdir "$_pkgdir/lib"
    mkdir "$_pkgdir/lib/pkgconfig"

    # Project assets
    cp "$_cargodir/target/release/inauth" "$_pkgdir"
    cp "$_cargodir/target/release/inauth_cli" "$_pkgdir"
    sed "s~{{sysconfdir}}~$sysconfdir~" < "$_cargodir/resources/auth.json.tpl" > "$_pkgdir/auth.json"
    case "$os" in
        "debian" | "ubuntu")
            cp "$_cargodir/resources/init/debian" "$_pkgdir/init"
            cp "$_cargodir/resources/init/systemd" "$_pkgdir/systemd"
            ;;
        "centos" | "fedora")
            cp "$_cargodir/resources/init/redhat" "$_pkgdir/init"
            cp "$_cargodir/resources/init/systemd" "$_pkgdir/systemd"
            ;;
        "freebsd")
            cp "$_cargodir/resources/init/freebsd" "$_pkgdir/init"
            ;;
    esac

    # ZeroMQ assets
    cp "$libdir/libzmq.$libext" "$_pkgdir/lib/"
    cp "$libdir/pkgconfig/libzmq.pc" "$_pkgdir/lib/pkgconfig/"
    cp "$prefix/include/zmq.h" "$_pkgdir/include/"

    # CZMQ assets
    cp "$libdir/libczmq.$libext" "$_pkgdir/lib/"
    cp "$libdir/pkgconfig/libczmq.pc" "$_pkgdir/lib/pkgconfig/"
    cp "$prefix/include/czmq.h" "$_pkgdir/include/"
    cp "$prefix/include/czmq_library.h" "$_pkgdir/include/"
    cp "$prefix/include/czmq_prelude.h" "$_pkgdir/include/"
    cp "$prefix/include/zactor.h" "$_pkgdir/include/"
    cp "$prefix/include/zarmour.h" "$_pkgdir/include/"
    cp "$prefix/include/zauth.h" "$_pkgdir/include/"
    cp "$prefix/include/zbeacon.h" "$_pkgdir/include/"
    cp "$prefix/include/zcert.h" "$_pkgdir/include/"
    cp "$prefix/include/zcertstore.h" "$_pkgdir/include/"
    cp "$prefix/include/zchunk.h" "$_pkgdir/include/"
    cp "$prefix/include/zclock.h" "$_pkgdir/include/"
    cp "$prefix/include/zconfig.h" "$_pkgdir/include/"
    cp "$prefix/include/zdigest.h" "$_pkgdir/include/"
    cp "$prefix/include/zdir.h" "$_pkgdir/include/"
    cp "$prefix/include/zdir_patch.h" "$_pkgdir/include/"
    cp "$prefix/include/zfile.h" "$_pkgdir/include/"
    cp "$prefix/include/zframe.h" "$_pkgdir/include/"
    cp "$prefix/include/zgossip.h" "$_pkgdir/include/"
    cp "$prefix/include/zhash.h" "$_pkgdir/include/"
    cp "$prefix/include/zhashx.h" "$_pkgdir/include/"
    cp "$prefix/include/ziflist.h" "$_pkgdir/include/"
    cp "$prefix/include/zlist.h" "$_pkgdir/include/"
    cp "$prefix/include/zlistx.h" "$_pkgdir/include/"
    cp "$prefix/include/zloop.h" "$_pkgdir/include/"
    cp "$prefix/include/zmonitor.h" "$_pkgdir/include/"
    cp "$prefix/include/zmsg.h" "$_pkgdir/include/"
    cp "$prefix/include/zpoller.h" "$_pkgdir/include/"
    cp "$prefix/include/zproxy.h" "$_pkgdir/include/"
    cp "$prefix/include/zrex.h" "$_pkgdir/include/"
    cp "$prefix/include/zsock.h" "$_pkgdir/include/"
    cp "$prefix/include/zstr.h" "$_pkgdir/include/"
    cp "$prefix/include/zsys.h" "$_pkgdir/include/"
    cp "$prefix/include/zuuid.h" "$_pkgdir/include/"

    # Configure installer.sh paths
    sed "s~{{prefix}}~$prefix~" < "$_cargodir/installer.sh" |
    sed "s~{{libdir}}~$libdir~" |
    sed "s~{{libext}}~$libext~" |
    sed "s~{{sysconfdir}}~$sysconfdir~" |
    sed "s~{{os}}~$os~" > "$_pkgdir/installer.sh"
    chmod u+x "$_pkgdir/installer.sh"

    local _pkgstoredir="$_cargodir/.pkg/$os"
    mkdir -p "$_pkgstoredir"

    local _tarball="$_pkgstoredir/$_pkgdir.tar.bz2"
    tar -cjf "$_tarball" "$_pkgdir"

    cd "$_cargodir"
}

main || exit 1
