#include "file_stat.hpp"

#include <libzip/zip.h>
#include <zipconf.h>

#include <sstream>

namespace zip_cpp {

std::string FileStat::toString() const noexcept {
  std::ostringstream builder;
  if (name) {
    builder << "name:" << name.value() << "; ";
  }
  if (index) {
    builder << "index:" << index.value() << "; ";
  }
  if (size) {
    builder << "size:" << size.value() << "; ";
  }
  if (size_compressed) {
    builder << "size_compressed:" << size_compressed.value() << "; ";
  }
  if (time_mod) {
    builder << "modification time:" << time_mod.value() << "; ";
  }
  if (crc) {
    builder << "crc:" << crc.value() << "; ";
  }
  if (comp_method) {
    builder << "comp_method:" << comp_method.value() << "; ";
  }
  if (encryption_method) {
    builder << "encryption_method:" << encryption_method.value() << "; ";
  }
  builder << "Encrypted:" << encrypted << ";";
  return builder.str();
}

}  // namespace zip_cpp