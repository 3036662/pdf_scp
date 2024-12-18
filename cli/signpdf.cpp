#include "options.hpp"
#include "tr.hpp"
#include <iostream>
#include <libintl.h>

int main(int argc, char *argv[]) {

  if (setlocale(LC_ALL, "") == nullptr) { // NOLINT
    std::cerr << "Failed to set locale.\n";
    return 1;
  }

  bindtextdomain(TRANSLATION_DOMAIN, TRANSLATIONS_DIR_COMPILED);
  bind_textdomain_codeset(TRANSLATION_DOMAIN, "UTF-8");
  textdomain(TRANSLATION_DOMAIN);

  // print help
  const pdfcsp::cli::Options options(argc, argv);
  if (options.help() || !options.AllMandatoryAreSet()) {
    return 0;
  }

  // check if all options are set

  return 0;
}