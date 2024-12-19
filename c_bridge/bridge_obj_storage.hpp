/* File: bridge_obj_storage.hpp
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#pragma once
#include <string>
#include <vector>

namespace pdfcsp::c_bridge {

/**
 * @brief Utility struct for storing STL objects
 */
struct BrigeObjStorage {
  std::string cades_t_str;
  std::string hashing_oid;
  std::vector<time_t> times_collection;
  std::vector<time_t> x_times_collection;
  std::vector<unsigned char> encrypted_digest;
  std::string cert_issuer;
  std::string cert_subject;
  std::vector<unsigned char> cert_public_key;
  std::vector<unsigned char> cert_serial;
  std::vector<unsigned char> cert_der_encoded;
  std::string cert_chain_json;
  std::string tsp_json_info;
  std::string signers_cert_ocsp_json_info;

  // cert_info - issuer
  std::string issuer_common_name;
  std::string issuer_email;
  std::string issuer_organization;
  // cert_info - subject
  std::string subj_common_name;
  std::string subj_email;
  std::string subj_organization;

  // json certificate list
  std::string user_certifitate_list_json;

  // raw signature (sign result)
  std::vector<unsigned char> raw_signature;
  // common error sring
  std::string err_string;
};

}  // namespace pdfcsp::c_bridge