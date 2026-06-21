#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>

#include "overtrust/types.hpp"

namespace overtrust {

// ── Node ─────────────────────────────────────────────────────────────────────

enum class NodeKind {
    Extension,
    Package,
    File,
    Process,
    Permission,
    Network,
    System,       // root node
};

struct GraphNode {
    std::string id;
    NodeKind    kind;
    std::string label;
    double      risk_score = 0.0;
    Severity    severity   = Severity::Info;

    // Extra metadata (key → value)
    std::unordered_map<std::string, std::string> meta;
};

// ── Edge ─────────────────────────────────────────────────────────────────────

enum class EdgeKind {
    DependsOn,
    Grants,
    Accesses,
    ConnectsTo,
    ContainsSecret,
    Runs,
};

struct GraphEdge {
    std::string from;
    std::string to;
    EdgeKind    kind;
    double      weight = 1.0;
    std::string label;
};

// ── Graph ─────────────────────────────────────────────────────────────────────

class TrustGraph {
public:
    // Mutators
    void add_node(GraphNode node);
    void add_edge(GraphEdge edge);

    // Queries
    bool has_node(const std::string& id) const;
    const GraphNode* get_node(const std::string& id) const;
    std::vector<std::string> neighbors(const std::string& id) const;

    // Algorithms
    std::unordered_set<std::string> reachable_from(const std::string& start) const;
    std::unordered_set<std::string> permission_closure(const std::string& ext_id) const;

    // Tarjan SCC — returns list of SCCs with size > 1 (cycles)
    std::vector<std::vector<std::string>> detect_cycles() const;

    // Betweenness centrality approximation (top-N nodes by path count)
    // Returns node IDs sorted by centrality desc
    std::vector<std::string> top_central_nodes(int n = 5) const;

    // Compute node risk from incoming edges (accumulates edge weights)
    void propagate_risk();

    // Serialise all nodes/edges to a simple text report
    std::string to_text() const;

    // Accessors for TUI rendering
    const std::vector<GraphNode>& nodes() const { return nodes_; }
    const std::vector<GraphEdge>& edges() const { return edges_; }

    std::size_t node_count() const { return nodes_.size(); }
    std::size_t edge_count() const { return edges_.size(); }

private:
    std::vector<GraphNode>                              nodes_;
    std::vector<GraphEdge>                              edges_;
    std::unordered_map<std::string, std::size_t>        id_to_idx_;   // id → nodes_ index
    std::unordered_map<std::string, std::vector<std::string>> adj_;   // adjacency list
};

// ── Build graph from scan findings ───────────────────────────────────────────

TrustGraph build_trust_graph(const std::vector<Finding>& findings);

// Compute trust score 0-100 from graph
int compute_trust_score(const TrustGraph& g);

} // namespace overtrust
