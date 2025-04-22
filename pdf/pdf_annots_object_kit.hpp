#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "annotation.hpp"
#include "form_x_object.hpp"
#include "image_obj.hpp"
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"

namespace pdfcsp::pdf {

struct SingleAnnot {
  Annotation annot;
  FormXObject form;
  ImageObj img;
  std::optional<ImageObj> img_mask;
};

struct PdfAnnotsObjectKit {
  ObjRawId original_last_id;  /// original doc last object id
  ObjRawId last_assigned_id;  /// last used id
  std::string users_tmp_dir;
  std::vector<SingleAnnot> annots;
  std::unordered_map<ObjRawId, std::vector<ObjRawId>> pages_for_update;
  std::vector<std::pair<ObjRawId, std::string>> pages_updated;
};

}  // namespace pdfcsp::pdf