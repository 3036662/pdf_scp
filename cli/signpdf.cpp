#include "options.hpp"
#include <iostream>
#include <libintl.h>
#include <spdlog/sinks/stdout_color_sinks.h>

int main(int argc, char *argv[]) {
  // setup the transtlator
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
  // setup logging
  auto console = spdlog::stdout_color_mt(TRANSLATION_DOMAIN);  
  if (!console){
    std::cerr <<tr("Setup logger failed");
  }  
  console->info("")


  return 0;
}