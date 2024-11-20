%define _unpackaged_files_terminate_build 1

Name: pdfcsp
Version: 0.1
Release: alt1
Summary: Library for CryptoPro pdf electronic signatures support.
License: %gpl2plus
Group: System/Libraries
Url: https://gitlab.basealt.space/proskurinov/csp_pdf

Source: %name-%version.tar

BuildPreReq: gcc-c++ cmake ninja-build rpm-macros-cmake rpm-build-licenses
BuildRequires: libqpdf-devel boost-devel-headers boost-interprocess-devel glibc-devel libsignimage_c_wrapper-devel libspdlog-devel libfmt-devel
%description
Library for CryptoPro pdf electronic signatures support.

%package -n libaltcsp
Summary: The shared library for CryptoPro 5 support.
Group: System/Libraries 
Requires: glibc-core glibc-pthread libspdlog libfmt
%description -n libaltcsp
The shared library for CryptoPro 5 support.

%package -n libaltcsp-devel
Summary: Developer headers for libaltcsp library
Group: Development/C
Requires: libaltcsp
%description -n libaltcsp-devel
Developer headers for libaltcsp 

%package -n libcspforpoppl-devel
Summary: Developer headers to use within the Poppler library
Group: Development/C
BuildArch: noarch
%description -n libcspforpoppl-devel
Summary: Developer headers to use within the Poppler library

%package -n libcsppdf
Summary: The shared library for pdf electronic signatures support.
Group: System/Libraries
Requires: libaltcsp 
%description -n libcsppdf 
The shared library for pdf electronic signatures support.

%package -n libcsppdf-devel
Summary: Developer headers for libcsppdf library
Group: Development/C
Requires: libcsppdf libqpdf-devel libsignimage_c_wrapper 
%description -n libcsppdf-devel 
Developer headers for libcsppdf 

%prep
%setup

%ifarch %ix86
%define _pvoid_size 4
%else
%define _pvoid_size 8
%endif

%build

%cmake -DCMAKE_BUILD_TYPE:STRING=Release -DSIZEOF_VOID_P=%_pvoid_size -DIPC_EXEC_DIR=%_usr/libexec/ -G Ninja
%cmake_build

%install libaltcsp
%cmake_install --config Release

%files -n libaltcsp
%_libdir/libaltcsp.so.0.1
%_libdir/libaltcsp.so.0
%_libdir/libcsp_c_bridge.so.0.1
%_libdir/libcsp_c_bridge.so.0

%_usr/libexec/altcspIpcProvider
%_libdir/libcsp_ipc_client.so.0.1
%_libdir/libcsp_ipc_client.so.0

%files -n libaltcsp-devel
%_libdir/libaltcsp.so
%_libdir/libcsp_c_bridge.so
%_libdir/libcsp_ipc_client.so

%_includedir/%name/altcsp.hpp
%_includedir/%name/message.hpp
%_includedir/%name/asn1.hpp
%_includedir/%name/certificate.hpp
%_includedir/%name/d_name.hpp
%_includedir/%name/ocsp.hpp
%_includedir/%name/resolve_symbols.hpp
%_includedir/%name/typedefs.hpp
%_includedir/%name/bool_results.hpp
%_includedir/%name/bridge_obj_storage.hpp
%_includedir/%name/c_bridge.hpp
%_includedir/%name/pod_structs.hpp
%_includedir/%name/ipc_client.hpp
%_includedir/%name/ipc_result.hpp
%_includedir/%name/ipc_typedefs.hpp
%_includedir/%name/cert_common_info.hpp
%_includedir/%name/logger_utils.hpp

%files -n libcspforpoppl-devel
%_includedir/%name/csp_for_poppl.hpp
%_includedir/%name/structs.hpp

%files -n libcsppdf
%_libdir/libcsppdf.so.0.1
%_libdir/libcsppdf.so.0

%files -n libcsppdf-devel
%_libdir/libcsppdf.so
%_includedir/%name/csppdf.hpp
%_includedir/%name/pdf_pod_structs.hpp
%_includedir/%name/pdf_structs.hpp
%_includedir/%name/pdf_defs.hpp
%_includedir/%name/pdf_update_object_kit.hpp
%_includedir/%name/acro_form.hpp
%_includedir/%name/form_x_object.hpp
%_includedir/%name/image_obj.hpp
%_includedir/%name/sig_field.hpp
%_includedir/%name/sig_val.hpp


%changelog
* Thu Aug 29 2024 Oleg Proskurin <proskur@altlinux.org> 0.1-alt1
- Initial build

