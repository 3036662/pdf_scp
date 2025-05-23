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


const std::string old_schema= test_files_dir +
  "valid/ON_DOVBB_20240828_cfeae40d-e613-48ff-989f-f6b45590e338.xml";

const std::string valid2= test_files_dir +
  "valid/ON_EMCHD_20250523_c59126b9-04c4-4df5-8497-c5ddb5309b87.xml";


const std::string valid3= test_files_dir +
  "valid/ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";

const std::string valid4= test_files_dir +
  "valid/ON_EMCHD_20250522_c52fc81d-c422-439f-b8e8-4d99a602f4d1.xml"  ;

const std::string valid5= test_files_dir +
  "valid/ON_EMCHD_20250523_46b84724-c65b-488e-a640-ec0498da68d8.xml" ;

const std::string valid6= test_files_dir +
  "valid/ON_EMCHD_20250523_323e64bf-0958-4c4f-a8ea-c026ee742cb4.xml" ;

const std::string valid7= test_files_dir +
  "valid/ON_EMCHD_20250523_472e846e-572b-4696-9ab1-ff839f9b0634.xml";