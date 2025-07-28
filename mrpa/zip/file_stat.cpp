#include "file_stat.hpp"

#include <libzip/zip.h>
#include <zipconf.h>

#include <boost/json/object.hpp>
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

boost::json::object FileStat::toJson() const {
  boost::json::object res;
  if (name) {
    res["name"] = name.value();
  }
  if (index) {
    res["index"] = index.value();
  }
  if (size) {
    res["size"] = size.value();
  }
  if (size_compressed) {
    res["size_compressed"] = size_compressed.value();
  }
  if (time_mod) {
    res["modification_time"] = time_mod.value();
  }
  if (crc) {
    res["crc"] = crc.value();
  }
  if (comp_method) {
    res["comp_method"] = comp_method.value();
  }
  if (encryption_method) {
    res["encryption_method"] = encryption_method.value();
  }
  res["encrypted"] = encrypted;
  return res;
}

}  // namespace zip_cpp