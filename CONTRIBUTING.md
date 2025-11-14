# Contributing to Project Name

## How to Contribute
1. Report bugs
2. Suggest features  
3. Submit pull requests
4. Improve documentation

## Development Setup

### Clone 
```bash 
# clone the dev branch
git clone https://gitlab.basealt.space/proskurinov/csp_pdf.git
cd csp_pdf
```
### Install dependencies
    gcc-c++ 
    cmake 
    ninja-build 
    libqpdf-devel 
    boost-devel-headers 
    boost-interprocess-devel 
    glibc-devel 
    libsignimage_c_wrapper-devel 
    libspdlog-devel 
    libfmt-devel
    boost-locale-devel 
    gettext-tools 
    boost-program_options-devel
    cppcodec-devel 
    zlib-devel 
    libzip-devel 
    libxml++3-devel

### Build
```bash 
cmake -S . -B build
cmake --build build
```

## Code Style
[CODESTYLE.md](CODESTYLE.md)

## Pull Request Guidelines
* Create a branch
* Make your changes 
* Submit the **Merge Request**.

## Issue Reporting
* Create Gitlab Issue [here](https://gitlab.basealt.space/proskurinov/csp_pdf/-/issues) 
* Or you can report via the [ALT Linux Bugzilla](https://bugzilla.altlinux.org/)