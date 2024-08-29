Name: pdfcsp
Version: 0.1
Release: alt1
Summary: Library for CryptoPro pdf electronic signatures support.
License: %gpl2plus
Group: System/Libraries
Url: https://gitlab.basealt.space/proskurinov/csp_pdf

Source: %name-%version.tar



#Requires: 
BuildPreReq: gcc-c++ cmake ninja-build rpm-macros-cmake rpm-build-licenses libqpdf-devel
%description
Library for CryptoPro pdf electronic signatures support.

%package -n libaltcsp
Summary: The shared library for CryptoPro 5 support.
Group: System/Libraries 
%description -n libaltcsp
The shared library for CryptoPro 5 support.

%package -n libcspforpoppl
Summary: The shared library for Poppler CSP support.
Group: System/Libraries
Requires: libaltcsp
%description -n libcspforpoppl
The shared library for Poppler CSP support.

%package -n libcsppdf
Summary: The shared library for pdf electronic signatures support.
Group: System/Libraries
Requires: libaltcsp libqpdf-devel
%description -n libcsppdf
 The shared library for pdf electronic signatures support.

%prep
%setup

%ifarch %ix86
%define _pvoid_size 4
%else
%define _pvoid_size 8
%endif

%build
%cmake -DCMAKE_BUILD_TYPE:STRING=Release -DSIZEOF_VOID_P=%_pvoid_size -G Ninja
%cmake_build

%install
%cmake_install --config Release

%files
%changelog
* Thu Aug 29 2024 Oleg Proskurin <proskur@altlinux.org> 0.1-alt1
- Initial build

