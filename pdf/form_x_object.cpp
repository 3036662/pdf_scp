#include "form_x_object.hpp"

namespace pdfcsp::pdf {

/*
Transformation matrix in pdf
[a b 0]
[c d 0]
[e f 0]

*/

std::string FormXObject::ToString() const {
  // build a stream
  std::string xstream;
  {
    Matrix matrix2{};
    matrix2.a = bbox.right_top.x;
    matrix2.d = bbox.right_top.y;
    std::ostringstream stream_builder;
    stream_builder << "q\n"
                   << matrix.toString() << " cm\n"
                   << matrix2.toString() << " cm\n"
                   << resources_img_tag_name << " " << "Do\n"
                   << "Q";
    xstream = stream_builder.str();
  }
  // build dict
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n"
          << kTagLength << " " << xstream.size() << "\n" // stream size
          << kTagType << " " << kTagXObject << "\n"
          << kTagSubType << " " << kTagForm << "\n"
          << kTagBBox << " " << bbox.ToString() << "\n"
          << kTagFormType << " " << form_type << "\n"
          << kTagResources << " " << kDictStart
          << "\n"
          // Resources dict fields
          << kTagXObject << " " << kDictStart
          << "\n"
          // Xobject nested dict
          << resources_img_tag_name << " " << resources_img_ref.ToStringRef()
          << "\n"
          << kDictEnd << "\n"  // end xobject dict
          << kDictEnd << "\n"  // end resources dict
          << kDictEnd << "\n"; // end this object dict
  // write a stream
  builder << kStreamStart << xstream << "\n" << kStreamEnd;
  builder << kObjEnd;
  return builder.str();
}

} // namespace pdfcsp::pdf