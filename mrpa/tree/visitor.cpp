#include "visitor.hpp"

#include <iostream>

#include "tree/node.hpp"

namespace mrpa {

void LookupTablesBuilder::Visit(FileNode& file) {
  id_maps_.all_nodes.insert_or_assign(file.id, file.weak_from_this());
  id_maps_.file_nodes.insert_or_assign(file.id, file.weak_from_this());
}

void LookupTablesBuilder::Visit(DirNode& dir) {
  id_maps_.all_nodes.insert_or_assign(dir.id, dir.weak_from_this());
}

void LookupTablesBuilder::Visit(ZipNode& zip) {
  id_maps_.all_nodes.insert_or_assign(zip.id, zip.weak_from_this());
  id_maps_.file_nodes.insert_or_assign(zip.id, zip.weak_from_this());
}

void LookupTablesBuilder::Visit(MrpaNode& mrpa) {
  id_maps_.all_nodes.insert_or_assign(mrpa.id, mrpa.weak_from_this());
  id_maps_.mrpa_nodes.insert_or_assign(mrpa.id, mrpa.weak_from_this());
}
void LookupTablesBuilder::Visit(SigNode& sig) {
  id_maps_.all_nodes.insert_or_assign(sig.id, sig.weak_from_this());
  id_maps_.sig_nodes.insert_or_assign(sig.id, sig.weak_from_this());
}

void LookupTablesBuilder::Visit(AsigNode& sig) {
  id_maps_.all_nodes.insert_or_assign(sig.id, sig.weak_from_this());
  id_maps_.sig_nodes.insert_or_assign(sig.id, sig.weak_from_this());
}

IdMaps LookupTablesBuilder::getTables() const noexcept { return id_maps_; }

}  // namespace mrpa