
#pragma once
#include "pdf_structs.hpp"

namespace pdfcsp::pdf {

/*
Transformation matrix in pdf
[a b 0]
[c d 0]
[e f 0]

*/

struct FormXObject {
  ObjRawId id;
  std::string type = kTagXObject;
  std::string subtype = kTagForm;
  BBox bbox; // An array of four numbers in the form coordinate system ,the
             // coordinates of the left, bottom, right, and top edges
             // respectively, of the form XObject’s bounding box.
  int form_type = 1;
  std::string resources_img_tag_name = "/img_sig1";
  ObjRawId resources_img_ref;
  Matrix matrix;

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf