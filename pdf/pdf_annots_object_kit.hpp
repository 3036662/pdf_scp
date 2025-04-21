#include "annotation.hpp"
#include "image_obj.hpp"
#include "pdf_structs.hpp"

namespace pdfcsp::pdf {

struct SingleAnnot {
  Annotation annot;
  ImageObj img;
  std::optional<ImageObj> img_mask;
};

struct PdfAnnotsObjectKit {
  ObjRawId original_last_id;  /// original doc last object id
  ObjRawId last_assigned_id;  /// last used id
  std::string users_tmp_dir;
};

}  // namespace pdfcsp::pdf