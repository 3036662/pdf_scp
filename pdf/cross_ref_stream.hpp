#pragma once
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace pdfcsp::pdf {

/*
Beginning with PDF 1.5, cross-reference information may be stored in a cross-
reference stream instead of in a cross-reference table. 
*/

struct CrossRefStream{
    ObjRawId id;
    std::string type= kTagXref; // /XRef    
    int size_val=0; // highest object number + 1

    /* /Index[....] - pair of integers for each subsection
     * pair: first_object_id => number_of_objects
     * this array must be soted by first field
     */ 
    std::vector<std::pair<int, int>> index_vec;
    
    /* /W Array
     * An array of integers representing the size of the fields in a single cross-
     * reference entry.
     * W always contains three integers
     */
    int w_field_0_size=1;
    int w_field_1_size=3;
    int w_field_2_size=2;

    // /Prev
    std::string prev_val;
    // /Root
    ObjRawId root_id;
    // Info
    std::optional<ObjRawId> info_id;
    /* /ID
     * An array of two byte-strings consti-tuting a file identifier 
     */
    std::optional<std::string> id_val;
    // /Length of data stream
    std::string length_tag=kTagLength;
};


} //namespace pdfcsp::pdf