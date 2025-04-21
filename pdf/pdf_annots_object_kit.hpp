#include "pdf_structs.hpp"


namespace pdfcsp::pdf {

struct PdfAnnotsObjectKit{
     ObjRawId original_last_id; /// original doc last object id
     ObjRawId last_assigned_id;  /// last used id
     std::string users_tmp_dir;
};  

} // namespace pdfcsp::pdf