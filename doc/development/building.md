# Building Cephtrace

This guide provides information about building cephtrace from source.

## Install dependencies
### Debian/Ubuntu

```bash
sudo apt-get install \
    g++ \
    clang \
    libelf-dev \
    libc6-dev \
    libc6-dev-i386 \
    libdw-dev
```

### RHEL/CentOS/Rocky Linux/Fedora

```bash
sudo dnf config-manager --enable crb  # Only for RHEL 9/CentOS Stream 9
sudo dnf install \
    g++ \
    clang \
    elfutils-libelf-devel \
    glibc-devel \
    glibc-devel.i686 \
    elfutils-devel
```

## Build

```bash
git clone https://github.com/taodd/cephtrace
cd cephtrace
git submodule update --init --recursive
make
```
