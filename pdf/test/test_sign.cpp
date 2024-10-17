#include "form_x_object.hpp"
#include "image_obj.hpp"
#include "pdf_structs.hpp"
#include "utils.hpp"
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFWriter.hh>
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