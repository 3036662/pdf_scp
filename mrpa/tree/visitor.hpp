#pragma once

#include "mrpa_typedefs.hpp"

namespace mrpa {

struct NodeBase;
struct FileNode;
struct DirNode;
struct ZipNode;
struct MrpaNode;
struct SigNode;
struct AsigNode;

/**
 * @brief Visitor base class
 * @details Visitor Pattern: Adds operations to classes without changing them
 * Node accept() visitors
 * Visitors implement visit() for each element type
 * Enables double dispatch (runtime type-specific behavior)
 */
class Visitor {
 public:
  Visitor() = default;
  Visitor(const Visitor&) = default;
  Visitor(Visitor&&) noexcept = default;
  Visitor& operator=(const Visitor&) = default;
  Visitor& operator=(Visitor&&) noexcept = default;

  virtual void Visit(FileNode&) = 0;
  virtual void Visit(DirNode&) = 0;
  virtual void Visit(ZipNode&) = 0;
  virtual void Visit(MrpaNode&) = 0;
  virtual void Visit(SigNode&) = 0;
  virtual void Visit(AsigNode&) = 0;

  virtual ~Visitor() = default;
};

/**
 * @brief Creates lookup tables for node
 * @details A lookup table maps an ID to a weak pointer.
 *
 */
class LookupTablesBuilder : public Visitor {
 public:
  void Visit(FileNode& file) override;
  void Visit(DirNode& dir) override;
  void Visit(ZipNode& zip) override;
  void Visit(MrpaNode& mrpa) override;
  void Visit(SigNode& sig) override;
  void Visit(AsigNode& asig) override;

  /// @brief Get the set of lookup tables
  IdMaps getTables() const noexcept;

 private:
  IdMaps id_maps_;  // all maps are stored here during the traverse
};

}  // namespace mrpa
