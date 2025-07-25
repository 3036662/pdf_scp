#pragma once

#include "node.hpp"

namespace mrpa {

class Visitor {
 public:
  Visitor() = default;
  Visitor(const Visitor&) = default;
  Visitor(Visitor&&) noexcept = default;
  Visitor& operator=(const Visitor&) = default;
  Visitor& operator=(Visitor&&) noexcept = default;

  virtual void VisitNode(Node&) = 0;
  virtual void VisitFile(FileNode&) = 0;
  virtual void VisitDir(DirNode&) = 0;
  virtual void VisitZip(ZipNode&) = 0;
  virtual void VisitMrpa(MrpaNode&) = 0;
  virtual void VisitSig(SigNode&) = 0;
  virtual void VisitAsig(AsigNode&) = 0;

  virtual ~Visitor() = 0;
};

class LookupTablesBuilder : public Visitor {
 public:
  void VisitNode(Node& node) override;
  void VisitFile(FileNode& file) override;
  void VisitDir(DirNode& dir) override;
  void VisitZip(ZipNode& zip) override;
  void VisitMrpa(MrpaNode& mrpa) override;
  void VisitSig(SigNode& sig) override;
  void VisitAsig(AsigNode& asig) override;

 private:
  std::unordered_map<uint64_t, PtrAssocNode> id_table_;
};

}  // namespace mrpa
