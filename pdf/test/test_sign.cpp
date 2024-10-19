#include "acro_form.hpp"
#include "form_x_object.hpp"
#include "image_obj.hpp"
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include "sig_field.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <memory>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <qpdf/QPDFWriter.hh>
#include <sstream>
#include <string>
#include <utility>
#define CATCH_CONFIG_MAIN
#include "common_defs.hpp"
#include "csppdf.hpp"
#include <catch2/catch.hpp>

constexpr const char *kFileSource = "source_empty.pdf";

using namespace pdfcsp::pdf;
using Qobj = QPDFObjectHandle;

void PrintDict(Qobj &obj) {
  for (auto &key : obj.getDictAsMap()) {
    std::cout << key.first << " " << key.second.unparse() << "\n";
  }
}

TEST_CASE("write_simple_copy") {
  const std::string source_file = std::string(TEST_FILES_DIR) + kFileSource;
  const std::string output_file = std::string(TEST_DIR) + "simple_copy.pdf";
  auto expected = FileToVector(source_file);
  REQUIRE(expected.has_value());
  REQUIRE(expected->size() == std::filesystem::file_size(source_file));
  // works
  std::ofstream ofile(output_file, std::ios_base::binary);
  REQUIRE(ofile.is_open());

  for (const auto &symbol : expected.value()) {
    ofile << symbol;
  }
  ofile.close();

  // doesn't work
  // QPDFWriter writer(*pdf->getQPDF());
  // writer.setOutputFilename(output_file.c_str());
  // writer.write();
  // writer.setPreserveUnreferencedObjects(true);
  // writer.setLinearization(false);
  // writer.setCompressStreams(false);
  // writer.setRecompressFlate(false);
  // writer.setContentNormalization(false);
  REQUIRE(std::filesystem::exists(output_file));
  auto result = FileToVector(output_file);
  REQUIRE(expected == result);
}

TEST_CASE("Extract_image") {
  // const std::string source_file =
  //     std::string(TEST_FILES_DIR) + "valid_files/09_cam_CADEST.pdf";
  const std::string source_file =
      std::string(TEST_FILES_DIR) + "valid_files/15_fns_1.pdf";
  std::cout << source_file << "\n";
  REQUIRE(std::filesystem::exists(source_file));
  std::ofstream img_file(std::string(TEST_DIR) + "img.bin",
                         std::ios_base::binary);
  std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(source_file);
  const auto &qpdf = pdf->getQPDF();
  auto obj_root = std::make_unique<QPDFObjectHandle>(qpdf->getRoot());
  REQUIRE(obj_root);
  REQUIRE_FALSE(obj_root->isNull());
  PrintDict(*obj_root);

  auto obj_form = obj_root->getKey("/AcroForm");
  REQUIRE_FALSE(obj_form.isNull());
  REQUIRE(obj_form.isDictionary());
  std::cout << "\nFORM:\n";
  PrintDict(obj_form);
  auto fields = obj_form.getKey("/Fields");

  auto field_0 = fields.getArrayItem(0);
  auto ap_fields = field_0.getKey("/AP");

  auto noraml_rep = ap_fields.getKey("/N");
  std::cout << noraml_rep.getTypeName() << "\n";
  std::cout << noraml_rep.unparse() << "\n";
  REQUIRE(noraml_rep.isStream());
  auto rep_dict = noraml_rep.getDict();
  REQUIRE_FALSE(rep_dict.isNull());
  std::cout << "REPRESENTATION STREAM DICT:\n";
  PrintDict(rep_dict);
  auto resources = rep_dict.getKey("/Resources");
  REQUIRE_FALSE(resources.isNull());
  std::cout << "\nRESOURCES:\n";
  PrintDict(resources);
  auto xobj = resources.getKey("/XObject");
  REQUIRE_FALSE(xobj.isNull());
  std::cout << "\nXobject\n";
  PrintDict(xobj);
  auto xobj_keys = xobj.getKeys();
  std::cout << "\nxobj key types:\n";
  for (const auto &key : xobj_keys) {
    auto key_val = xobj.getKey(key);
    std::cout << "key:" << key << " val type:" << key_val.getTypeName() << "\n";
    if (key_val.isStream()) {
      std::cout << "\n";
      auto stream_val = key_val.getDict();
      REQUIRE_FALSE(stream_val.isNull());
      std::cout << "stream dict val\n";
      PrintDict(stream_val);
      auto width = stream_val.getKey("/Width").getUIntValue();
      auto height = stream_val.getKey("/Height").getUIntValue();

      std::cout << "\n";
      auto data = key_val.getRawStreamData();
      REQUIRE(data);
      size_t data_size = data->getSize();
      std::cout << "data size: " << data_size << "\n";
      REQUIRE(data_size > 0);
      unsigned char *pdata = data->getBuffer();
      img_file << "P6\n"; // Binary PPM
      img_file << width << " " << height << "\n";
      img_file << "255\n"; // Max color value
      // NOLINTBEGIN
      img_file.write(reinterpret_cast<const char *>(pdata), data_size);
      // NOLINTEND
    }
  }
  img_file.close();
  REQUIRE_FALSE(std::filesystem::is_empty(std::string(TEST_DIR) + "img.bin"));
}

TEST_CASE("LastID") {
  const std::string source_file = std::string(TEST_FILES_DIR) + kFileSource;
  std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(source_file);
  const ObjRawId last_id = pdf->GetLastObjID();
  REQUIRE(last_id.id == 11);
  REQUIRE(last_id.gen == 0);
}

TEST_CASE("CreateImageObject") {
  const std::string img_data = std::string(TEST_FILES_DIR) + "img_data_raw.bin";
  SECTION("Empty") {
    ImageObj tmp;
    std::string str = tmp.ToString();
    REQUIRE(str == "0 0 obj\n<<\n/Type /XObject\n/Subtype /Image\n"
                   "/Width 0\n/Height 0\n/ColorSpace /DeviceRGB\n"
                   "/BitsPerComponent 0\n/Length 0\n>>\n");
  }
  SECTION("SomeData") {
    ImageObj tmp;
    tmp.data = BytesVector(100, 0xFF);
    tmp.width = 100;
    tmp.height = 200;
    std::string str = tmp.ToString();
    REQUIRE(str == "0 0 obj\n<<\n/Type /XObject\n/Subtype /Image\n"
                   "/Width 100\n/Height 200\n/ColorSpace /DeviceRGB\n"
                   "/BitsPerComponent 0\n/Length 100\n>>\n");
  }

  SECTION("RawData") {
    ImageObj tmp;
    tmp.data = BytesVector(100, 0xFF);
    tmp.width = 100;
    tmp.height = 200;
    BytesVector raw_data = tmp.ToRawData();
    REQUIRE(raw_data.size() == tmp.ToString().size() + tmp.data.size() + 25);
  }

  SECTION("FromFile") {
    ImageObj tmp;
    auto buf = FileToVector(std::string(TEST_FILES_DIR) + "img_data_raw.bin");
    REQUIRE(buf);
    REQUIRE_FALSE(buf->empty());
    tmp.data = std::move(buf.value());
    BytesVector raw_data = tmp.ToRawData();
    REQUIRE(raw_data.size() == tmp.ToString().size() + tmp.data.size() + 25);
  }
}

TEST_CASE("BBox") {
  SECTION("DoubleToString") {
    REQUIRE(DoubleToString10(0) == "0");
    REQUIRE(DoubleToString10(0.0) == "0");
    REQUIRE(DoubleToString10(0.000000) == "0");
    REQUIRE(DoubleToString10(-0.000000) == "0");
    REQUIRE(DoubleToString10(-0.0000000001) == "-0.0000000001");
    REQUIRE(DoubleToString10(-0.00000000001000100000) == "0");
    REQUIRE(DoubleToString10(0.0000000001000100000) == "0.0000000001");
  }
  const BBox bbox{{0, 0.000003434121212}, {255, 100.124324454664654}};
  REQUIRE(bbox.ToString() == "[ 0 0.0000034341 255 100.1243244547 ]");
}

TEST_CASE("Matrix") {
  Matrix matrix;
  REQUIRE(matrix.toString() == "1 0 0 1 0 0");
}

TEST_CASE("FormXObject") {
  FormXObject xobj;
  const std::string def_xfobj = xobj.ToString();
  const std::string expected = "0 0 obj\n"
                               "<<\n"
                               "/Length 46\n"
                               "/Type /XObject\n"
                               "/Subtype /Form\n"
                               "/BBox [ 0 0 0 0 ]\n"
                               "/FormType 1\n"
                               "/Resources <<\n"
                               "/XObject <<\n"
                               "/img_sig1 0 0 R\n"
                               ">>\n"
                               ">>\n"
                               ">>\n"
                               "stream\n"
                               "q\n"
                               "1 0 0 1 0 0 cm\n"
                               "0 0 0 0 0 0 cm\n"
                               "/img_sig1 Do\n"
                               "Q\n"
                               "endstream\n"
                               "endobj\n";
  REQUIRE(def_xfobj == expected);
  std::cout << def_xfobj;
}

TEST_CASE("Acroform") {
  AcroForm acr;
  acr.fields.push_back({});
  const std::string res = acr.ToString();
  const std::string expected = "0 0 obj\n"
                               "<<\n"
                               "/Fields [ 0 0 R ]\n"
                               "/SigFlags 3\n"
                               ">>\n"
                               "endobj\n";
  REQUIRE(res == expected);
  std::cout << res;
}

TEST_CASE("SigField") {
  SigField sigf;
  const std::string expected = "0 0 obj\n"
                               "<<\n"
                               "/FT /Sig\n"
                               "/F 4\n"
                               "/Type /Annot\n"
                               "/Subtype /Widget\n"
                               "/P 0 0 R\n"
                               "/Rect [ 0 0 0 0 ]\n"
                               "/AP <<\n"
                               "/N 0 0 R\n"
                               ">>\n"
                               ">>\n"
                               "endobj\n";
  REQUIRE(sigf.ToString() == expected);
  std::cout << sigf.ToString();
}

TEST_CASE("find_and_copy_acroform") {
  const std::string source_file = std::string(TEST_FILES_DIR) + "cam_bes1.pdf";
  std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(source_file);
  PtrPdfObjShared acroform = pdf->GetAcroform();
  REQUIRE(acroform);
  auto copy = AcroForm::ShallowCopy(acroform);
  std::string res = copy.ToString();
  std::string expected = "14 0 obj\n"
                         "<<\n"
                         "/Fields [ 13 0 R ]\n"
                         "/SigFlags 3\n"
                         ">>\n"
                         "endobj\n";
  REQUIRE(res == expected);
}

TEST_CASE("FindXrefOffset") {
  SECTION("1") {
    auto buf = FileToVector(std::string(TEST_FILES_DIR) +
                            "valid_files/01_okular_BES.pdf");
    REQUIRE(buf);
    auto res = FindXrefOffset(buf.value());
    REQUIRE(res);
    REQUIRE(res.value() == "508614");
  }
  SECTION("2") {
    auto buf = FileToVector(std::string(TEST_FILES_DIR) +
                            "valid_files/02_cam_BES.pdf");
    REQUIRE(buf);
    auto res = FindXrefOffset(buf.value());
    REQUIRE(res);
    REQUIRE(res.value() == "2813580");
  }
  SECTION("10") {
    auto buf = FileToVector(
        std::string(TEST_FILES_DIR) +
        "valid_files/"
        "10_cam_CADEST_signers_free_area_signedCadesT_plus_cadesT.pdf");
    REQUIRE(buf);
    auto res = FindXrefOffset(buf.value());
    REQUIRE(res);
    REQUIRE(res.value() == "4785507");
  }
}

TEST_CASE("low_level_build_without_sig_val") {
  const std::string source_file = std::string(TEST_FILES_DIR) + kFileSource;
  std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(source_file);
  // find an ID of last object in the document
  const ObjRawId last_id = pdf->GetLastObjID();
  std::cout << "last id = " << last_id.ToString() << "\n";
  PtrPdfObjShared p_acroforom = pdf->GetAcroform();
  REQUIRE_FALSE(p_acroforom); // no acroform in this doc
  // ------------------------------
  // create image
  ImageObj img_obj;
  const std::string img_file = std::string(TEST_FILES_DIR) + "img_data_raw.bin";
  REQUIRE(std::filesystem::exists(img_file));
  REQUIRE(img_obj.ReadFile(img_file, 932, 296, 8));
  // Assign an id for newly created obj
  ObjRawId last_assigned_id{last_id.id + 1, 0};
  img_obj.id = last_assigned_id;
  // find page 0
  auto page_0 = pdf->GetPage(0);
  REQUIRE(page_0);
  auto page_rect = PageRect(page_0);
  REQUIRE(page_rect);
  // std::cout << "Page rect" << page_rect->ToString() << "\n";
  const bool landscape = page_rect->right_top.x > page_rect->right_top.y;
  // ------------------------------
  // create xform obj
  FormXObject form_x_object;
  form_x_object.id = ++last_assigned_id; // assign new id
  form_x_object.bbox.right_top.x =
      landscape ? page_rect->right_top.x / 3 : page_rect->right_top.x * 0.42;
  form_x_object.bbox.right_top.y =
      landscape ? page_rect->right_top.y / 7 : page_rect->right_top.y * 0.11;
  form_x_object.resources_img_ref = img_obj.id; // image id
  std::string expected =
      "13 0 obj\n<<\n/Length 71\n/Type /XObject\n/Subtype /Form\n/BBox [ 0 0 "
      "250.0276535433 92.6078740157 ]\n/FormType 1\n/Resources <<\n/XObject "
      "<<\n/img_sig1 12 0 R\n>>\n>>\n>>\nstream\nq\n1 0 0 1 0 0 "
      "cm\n250.0276535433 0 0 92.6078740157 0 0 cm\n/img_sig1 "
      "Do\nQ\nendstream\nendobj\n";
  REQUIRE(expected == form_x_object.ToString());
  // ------------------------------
  // create sig field
  SigField sig_field;
  sig_field.id = ++last_assigned_id;
  // parent page
  sig_field.parent = ObjRawId{page_0->getObjectID(), page_0->getGeneration()};
  sig_field.name = "test_annot";
  // appearance - form xobject
  sig_field.appearance_ref = form_x_object.id;
  sig_field.rect.left_bottom.x = 200;
  sig_field.rect.left_bottom.y = 200;
  sig_field.rect.right_top.x = 200 + form_x_object.bbox.right_top.x;
  sig_field.rect.right_top.y = 200 + form_x_object.bbox.right_top.y;
  const std::string expected_sig_field =
      "14 0 obj\n<<\n/FT /Sig\n/F 4\n/T (test_annot)\n/Type /Annot\n/Subtype "
      "/Widget\n/P 1 0 R\n/Rect [ 200 200 450.0276535433 292.6078740157 ]\n/AP "
      "<<\n/N 13 0 R\n>>\n>>\nendobj\n";
  REQUIRE(sig_field.ToString() == expected_sig_field);
  // ------------------------------
  // create acroform
  REQUIRE_FALSE(pdf->GetAcroform()); // No acroform
  AcroForm acroform;
  acroform.id = ++last_assigned_id;
  acroform.fields.push_back(sig_field.id);
  std::string acr_expected =
      "15 0 obj\n<<\n/Fields [ 14 0 R ]\n/SigFlags 3\n>>\nendobj\n";
  REQUIRE(acr_expected == acroform.ToString());
  // ------------------------------
  // copy page
  // TODO(Oleg) move to utils test append annots
  REQUIRE_FALSE(page_0->hasKey(kTagAnnots)); // no annots on this page
  auto unparsed_map = DictToUnparsedMap(*page_0);
  REQUIRE(unparsed_map.count(kTagAnnots) == 0);
  // insert annots
  std::string annots_unparsed_val;
  {
    std::ostringstream builder;
    builder << "[ " << sig_field.id.ToStringRef() << " ]";
    annots_unparsed_val = builder.str();
  }
  unparsed_map[kTagAnnots] = annots_unparsed_val;
  std::string page_unparsed;
  {
    std::ostringstream builder;
    builder << ObjRawId::CopyIdFromExisting(*page_0).ToString() << " \n"
            << kDictStart << "\n";
    builder << UnparsedMapToString(unparsed_map);
    builder << kDictEnd << "\n" << kObjEnd;
    page_unparsed = builder.str();
  }

  REQUIRE(page_unparsed ==
          "1 0 obj \n<<\n/Annots [ 14 0 R ]\n/Contents 2 0 R\n/MediaBox [ "
          "0 0 595.303937007874 841.889763779528 ]\n/Parent 5 0 "
          "R\n/Resources 7 0 R\n/Type /Page\n>>\nendobj\n");

  // ------------------------------
  // copy root
  auto root = pdf->GetRoot();
  REQUIRE(root);
  REQUIRE(root->isDictionary());
  std::string root_updated;
  {
    std::ostringstream builder;
    builder << ObjRawId::CopyIdFromExisting(*root).ToString() << "\n"
            << kDictStart << "\n";
    auto root_unparsed_map = DictToUnparsedMap(*root);
    REQUIRE(root_unparsed_map.count(kTagAcroForm) == 0); // no acroform
    root_unparsed_map[kTagAcroForm] = acroform.id.ToStringRef();
    builder << UnparsedMapToString(root_unparsed_map);
    builder << kDictEnd << "\n" << kObjEnd;
    root_updated = builder.str();
  }
  std::cout << root_updated;
  // ------------------------------
  // create xref
  // new objects : img_obj,form_x_object,sig_field,acroform
  // updated objects: page_unparsed,root_updated
  std::cout << "\n"
            << img_obj.id.ToString() << "\n"
            << form_x_object.id.ToString() << "\n"
            << sig_field.id.ToString() << "\n"
            << acroform.id.ToString() << "\n"
            << ObjRawId::CopyIdFromExisting(*page_0).ToString() << "\n" // page
            << ObjRawId::CopyIdFromExisting(*root).ToString() << "\n";  // root
  // 10 gidit offset + 5 digit generation + n symbol
  // total 20 bytes
  auto file_buff = FileToVector(source_file);

  REQUIRE(file_buff.has_value());
  REQUIRE_FALSE(file_buff->empty());
  std::cout << "Source file size = " << file_buff->size() << "\n";
  // push updated page
  std::vector<XRefEntry> ref_entries;
  ref_entries.emplace_back(
      XRefEntry{ObjRawId::CopyIdFromExisting(*page_0), file_buff->size(), 0});
  std::copy(page_unparsed.cbegin(), page_unparsed.cend(),
            std::back_inserter(*file_buff));
  REQUIRE(ref_entries[0].ToString().size() == 20);
  std::cout << ref_entries[0].ToString();
  // push update root
  ref_entries.emplace_back(
      XRefEntry{ObjRawId::CopyIdFromExisting(*root), file_buff->size(), 0});
  std::copy(root_updated.cbegin(), root_updated.cend(),
            std::back_inserter(*file_buff));
  REQUIRE(ref_entries[1].ToString().size() == 20);
  std::cout << ref_entries[1].ToString();
  // push the image
  ref_entries.emplace_back(XRefEntry{img_obj.id, file_buff->size(), 0});
  {
    auto raw_img_obj = img_obj.ToRawData();
    std::copy(raw_img_obj.cbegin(), raw_img_obj.cend(),
              std::back_inserter(*file_buff));
  }
  REQUIRE(ref_entries[2].ToString().size() == 20);
  std::cout << ref_entries[2].ToString();
  // push x_object
  ref_entries.emplace_back(XRefEntry{form_x_object.id, file_buff->size(), 0});
  {
    auto raw_img_obj = form_x_object.ToString();
    std::copy(raw_img_obj.cbegin(), raw_img_obj.cend(),
              std::back_inserter(*file_buff));
  }
  REQUIRE(ref_entries[3].ToString().size() == 20);
  std::cout << ref_entries[3].ToString();
  // push the sig field
  ref_entries.emplace_back(XRefEntry{sig_field.id, file_buff->size(), 0});
  {
    auto raw_sig_field = sig_field.ToString();
    std::copy(raw_sig_field.cbegin(), raw_sig_field.cend(),
              std::back_inserter(*file_buff));
  }
  REQUIRE(ref_entries[4].ToString().size() == 20);
  std::cout << ref_entries[4].ToString();
  // push the acroform
  ref_entries.emplace_back(XRefEntry{acroform.id, file_buff->size(), 0});
  {
    auto raw_acroform = acroform.ToString();
    std::copy(raw_acroform.cbegin(), raw_acroform.cend(),
              std::back_inserter(*file_buff));
  }
  REQUIRE(ref_entries[5].ToString().size() == 20);
  std::cout << ref_entries[5].ToString();
  // ------------------------------
  // create new trailer
  auto trailer_orig = pdf->GetTrailer();
  REQUIRE(trailer_orig);
  REQUIRE(trailer_orig->isDictionary());
  auto map_unparsed = DictToUnparsedMap(*trailer_orig);
  // find old xref offset
  auto prev_x_ref = FindXrefOffset(*file_buff);
  REQUIRE(prev_x_ref);
  map_unparsed.insert_or_assign(kTagPrev, prev_x_ref.value());
  map_unparsed.erase(kDocChecksum);
  std::string raw_trailer = "trailer\n<<";
  raw_trailer += UnparsedMapToString(map_unparsed);
  raw_trailer += ">>\n";
  // ------------------------------
  // complete the file
  // push xref_table to file
  const size_t xref_table_offset = file_buff->size();
  const std::string raw_xref_table = BuildXrefRawTable(ref_entries);
  std::copy(raw_xref_table.cbegin(), raw_xref_table.cend(),
            std::back_inserter(*file_buff));
  std::copy(raw_trailer.cbegin(), raw_trailer.cend(),
            std::back_inserter(*file_buff));
  // final info
  {
    std::string final_info = kStartXref;
    final_info += "\n";
    final_info += std::to_string(xref_table_offset);
    final_info += "\n";
    final_info += kEof;
    final_info += "\n";
    std::cout << final_info;
    std::copy(final_info.cbegin(), final_info.cend(),
              std::back_inserter(*file_buff));
  }
  // ------------------------------
  // write the file
  const std::string output_file = std::string(TEST_DIR) + "output1.pdf";
  std::ofstream ofile(output_file, std::ios_base::binary);
  for (const auto symbol : file_buff.value()) {
    ofile << symbol;
  }
  ofile.close();
}

TEST_CASE("incremental_update") {
  const std::string source_file = std::string(TEST_FILES_DIR) + kFileSource;
  std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(source_file);

  SECTION("create_annot") {
    const auto &qpdf = pdf->getQPDF();
    auto annot = QPDFObjectHandle::newDictionary();
    // std::cout << qpdf->getObjectCount();
    // auto xref = qpdf->getXRefTable();
    // for (const auto &xref_pair : xref) {
    //   std::cout << xref_pair.first. << "\n";
    // }
    auto objects = qpdf->getAllObjects();
    for (auto &obj : objects) {
      std::cout << obj.getObjectID() << "\n";
      std::cout << obj.getGeneration() << "\n";
    }
  }

  SECTION("Copy page") {
    const std::string output_file = std::string(TEST_DIR) + "output1.pdf";
    auto obj_root =
        std::make_unique<QPDFObjectHandle>(pdf->getQPDF()->getRoot());
    // const auto &qpdf = pdf->getQPDF();
    REQUIRE(obj_root);
    REQUIRE_FALSE(obj_root->isNull());
    std::cout << "Root " << obj_root->unparse() << "\n";
    // qpdf->showXRefTable();
    REQUIRE(obj_root->hasKey("/Pages"));
    auto pages = std::make_unique<Qobj>(obj_root->getKey("/Pages"));
    REQUIRE(pages);
    REQUIRE_FALSE(pages->isNull());
    std::cout << "Pages " << pages->unparse() << "\n";
    REQUIRE(pages->isDictionary());
    // for (const auto &key : pages->getKeys()) {
    //   std::cout << key << "\n";
    // }
    REQUIRE(pages->hasKey("/Kids"));
    auto kids = std::make_unique<Qobj>(pages->getKey("/Kids"));
    REQUIRE(kids);
    REQUIRE_FALSE(kids->isNull());
    std::cout << "Kids " << kids->unparse() << "\n";
    REQUIRE(kids->isArray());
    REQUIRE(kids->getArrayNItems() > 0);
    auto page_0 = std::make_unique<Qobj>(kids->getArrayItem(0));
    REQUIRE(page_0->isDictionary());
    REQUIRE((page_0 && !page_0->isNull()));
    for (auto &key : page_0->getDictAsMap()) {
      std::cout << key.first << " " << key.second.unparse() << "\n";
    }

    // copy page object
    Qobj page_copy = page_0->shallowCopy();
    REQUIRE_FALSE(page_copy.isNull());
    std::cout << "page copy: " << page_copy.unparse() << "\n";
    std::cout << page_0->getObjectID() << " " << page_0->getGeneration()
              << " obj" << std::endl;
    std::cout << page_copy.getObjectID() << " " << page_copy.getGeneration()
              << " obj" << std::endl;

    // add /Annots to page
    Qobj annots_for_page = QPDFObjectHandle::newArray();
    // page_copy.replaceKey("/Annots", )

    // copy source file
    auto source_buff = FileToVector(source_file);
    std::ofstream ofile(output_file, std::ios_base::binary);
    REQUIRE(ofile.is_open());
    for (const auto &symbol : source_buff.value()) {
      ofile << symbol;
    }

    // add new page object
    ofile << page_0->getObjectID() << " " << page_0->getGeneration() << " "
          << "obj\n"
          << "<<";
    auto page_fields = page_0->getDictAsMap();
    for (auto &key : page_fields) {
      ofile << key.first << " " << key.second.unparse() << "\n";
    }
    ofile << ">>\n" << "endobj\n";

    ofile.close();
  }
}