#pragma once

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::cli {

namespace po = boost::program_options;

const char *const kInputFileTag = "input-file,i";
const char *const kHelpTag = "help,h";
const char *const kPageNumberTag = "page-number,p";
const char *const kXTag = "x";
const char *const kYTag = "y";
const char *const kWidthTag = "width,w";
const char *const kHeightTag = "height,h";
const char *const kLogoTag = "logo,l";
const char *const kOutputDIRTag = "output-dir,-d";
const char *const kOutputPostfixTag = "output-file-postfix,P";

class Options {
private:
  po::positional_options_description pos_opt_desc_;
  po::options_description description_;

  [[nodiscard]] static std::string ResolvePath(const std::string &path);

  bool wrong_params = false;
  po::variables_map var_map_;

public:
  Options(int argc, char **&argv);
  [[nodiscard]] bool help() const;
};

} // namespace pdfcsp::cli