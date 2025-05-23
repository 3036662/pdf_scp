#pragma once
#include <string>
const std::string test_files_dir = std::string(TEST_FILES_DIR) + "mrpa/";
const std::string mrpa_scheme =
  test_files_dir + "valid/ON_EMCHD_1_928_00_01_01_01.xsd";

const std::string file_name_tmpl_head= test_files_dir + "invalid/invalid_";
const std::string file_name_tmpl_tail ="_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";


const std::string mrpa1_valid =
  test_files_dir +
  "valid/ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
const std::string mrpa1_invalid_broken =
  test_files_dir +
  "invalid/ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";

const std::string mrpa_deleted_el1 =
  test_files_dir +
  "invalid/"
  "delete_field_1_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";

const std::string mrpa_deleted_el2 =
  test_files_dir +
  "invalid/"
  "delete_field_2_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";

const std::string mrpa_deleted_el3 =
  test_files_dir +
  "invalid/"
  "delete_field_3_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";

const std::string mrpa_deleted_el4 =
  test_files_dir +
  "invalid/"
  "delete_field_4_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";


const std::string mrpa_invalid_length_5 =
  test_files_dir +
  "invalid/"
  "invalid_length_5_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";

const std::string mrpa_invalid_deleted_attr6 =
  test_files_dir +
  "invalid/"
  "delete_attr_6_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";


const std::string mrpa_invalid_unxpected_attr_7 =
  test_files_dir +
  "invalid/"
"unexpcted_attr_7_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
