#pragma once

/* File: visitor.hpp
Copyright (C) Basealt LLC,  2025
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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

/**
 * @brief Removes all expired references from NODE.refs and NODE.mrpa_refs
 * @details A lookup table maps an ID to a weak pointer.
 *
 */
class RefsCleaner : public Visitor {
 public:
  void Visit(FileNode& file) override;
  void Visit(DirNode& dir) override;
  void Visit(ZipNode& zip) override;
  void Visit(MrpaNode& mrpa) override;
  void Visit(SigNode& sig) override;
  void Visit(AsigNode& asig) override;

 private:
  /// @brief Housekeeping function to delete references to all expired nodes
  static void CleanOneNode(NodeBase& node);
};

}  // namespace mrpa
