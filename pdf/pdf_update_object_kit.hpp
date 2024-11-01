#include "acro_form.hpp"
#include "form_x_object.hpp"
#include "image_obj.hpp"
#include "pdf_structs.hpp"
#include "sig_field.hpp"
#include <optional>
#include <vector>
namespace pdfcsp::pdf {

struct PdfUpdateObjectKit {
  ObjRawId original_last_id; /// original doc last object id
  ObjRawId last_assigned_id; /// last used id
  std::string users_tmp_dir;
  PtrPdfObjShared p_page_original; /// pointer to original page object
  PtrPdfObjShared p_root_original;
  std::optional<BBox> origial_page_rect;

  ImageObj image_obj; // stamp image
  FormXObject form_x_object;
  SigField sig_field;
  AcroForm acroform;
  std::string updated_page;           // page raw data
  std::string root_updated;           // root object raw
  std::vector<XRefEntry> ref_entries; // XRef

  std::vector<unsigned char> updated_file_data;
};

} // namespace pdfcsp::pdf