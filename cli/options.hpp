#pragma once

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::cli {

namespace po = boost::program_options;

const char *const kInputFileTag = "input-file,i";
const char *const kInputFileTagL = "input-file";
const char *const kHelpTag = "help,h";
const char *const kHelpTagL = "help";
const char *const kPageNumberTag = "page-number,p";
const char *const kPageNumberTagL = "page-number";

const char *const kXTag = "x,X";
const char *const kXTagL = "x";
const char *const kYTag = "y,Y";
const char *const kYTagY = "y";
const char *const kWidthTag = "width,W";
const char *const kWidthTagL = "width";
const char *const kHeightTag = "height,H";
const char *const kHeightTagL = "height";
const char *const kLogoTag = "logo,l";
const char *const kOutputDIRTag = "output-dir,d";
const char *const kOutputDIRTagL = "output-dir";
const char *const kOutputPostfixTag = "output-file-postfix,P";

class Options {
public:
  Options(int argc, char **&argv);

  [[nodiscard]] bool help() const;
  [[nodiscard]] bool AllMandatoryAreSet() const;
  [[nodiscard]] bool WrongParams() const { return wrong_params_; }

private:
  [[nodiscard]] static std::string ResolvePath(const std::string &path);

  po::positional_options_description pos_opt_desc_;
  po::options_description description_;
  bool wrong_params_ = false;
  po::variables_map var_map_;
};

} // namespace pdfcsp::cli