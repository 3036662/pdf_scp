#include "visitor.hpp"

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
  id_maps_.asig_nodes.insert_or_assign(sig.id, sig.weak_from_this());
}

IdMaps LookupTablesBuilder::getTables() const noexcept { return id_maps_; }

// refs cleaner visitor
void RefsCleaner::Visit(FileNode& file) { CleanOneNode(file); }
void RefsCleaner::Visit(DirNode& dir) { CleanOneNode(dir); }
void RefsCleaner::Visit(ZipNode& zip) { CleanOneNode(zip); }
void RefsCleaner::Visit(MrpaNode& mrpa) { CleanOneNode(mrpa); }
void RefsCleaner::Visit(SigNode& sig) { CleanOneNode(sig); }
void RefsCleaner::Visit(AsigNode& sig) { CleanOneNode(sig); }

/// @brief Housekeeping function to delete references to all expired nodes
void RefsCleaner::CleanOneNode(NodeBase& node) {
  auto& refs = node.refs;
  // remove refs to all expired  nodes
  std::vector<NodeId> expired_refs;
  expired_refs.reserve(5);
  std::for_each(refs.cbegin(), refs.cend(),
                [&expired_refs](const NodeIdMap::value_type& pval) {
                  if (pval.second.expired()) {
                    expired_refs.emplace_back(pval.first);
                  }
                });
  std::for_each(expired_refs.cbegin(), expired_refs.cend(),
                [&refs](NodeId key) { refs.erase(key); });

  // remove refs to expired MRPAs
  auto& mrpas = node.mrpa_refs;
  std::vector<NodeId> expired_mrpa_refs;
  expired_mrpa_refs.reserve(5);
  std::for_each(mrpas.cbegin(), mrpas.cend(),
                [&expired_mrpa_refs](const NodeIdMap::value_type& pval) {
                  if (pval.second.expired()) {
                    expired_mrpa_refs.emplace_back(pval.first);
                  }
                });
  std::for_each(expired_mrpa_refs.cbegin(), expired_mrpa_refs.cend(),
                [&mrpas](NodeId key) { mrpas.erase(key); });
}

}  // namespace mrpa