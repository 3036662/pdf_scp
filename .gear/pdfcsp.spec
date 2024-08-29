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

%package libaltcsp
Summary: The shared library for CryptoPro 5 support.
Group: System/Libraries
#Requires: 
%description libaltcsp
The shared library for CryptoPro 5 support.

%package libcspforpoppl
Summary: The shared library for Poppler CSP support.
Group: System/Libraries
#Requires: libaltcsp
%description libaltcsp
The shared library for Poppler CSP support.

%prep
%setup

%ifarch %ix86
%define PVOID=4
%else
%define PVOID=8
%endif

%build
%cmake -DCMAKE_BUILD_TYPE:STRING=Release -DSIZEOF_VOID_P=%PVOID -G Ninja
%cmake_build

%install
%cmake_install --config Release

%files