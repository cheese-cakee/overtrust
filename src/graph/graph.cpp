#include "overtrust/graph.hpp"

#include <filesystem>
#include <algorithm>
#include <sstream>
#include <queue>
#include <climits>

namespace overtrust {

// ── TrustGraph: mutators ──────────────────────────────────────────────────────

void TrustGraph::add_node(GraphNode node) {
    if (id_to_idx_.count(node.id)) {
        // Update existing node's score if higher
        auto& existing = nodes_[id_to_idx_[node.id]];
        if (node.risk_score > existing.risk_score) {
            existing.risk_score = node.risk_score;
            existing.severity   = node.severity;
        }
        return;
    }
    id_to_idx_[node.id] = nodes_.size();
    adj_[node.id]; // ensure entry exists
    nodes_.push_back(std::move(node));
}

void TrustGraph::add_edge(GraphEdge edge) {
    adj_[edge.from].push_back(edge.to);
    edges_.push_back(std::move(edge));
}

bool TrustGraph::has_node(const std::string& id) const {
    return id_to_idx_.count(id) > 0;
}

const GraphNode* TrustGraph::get_node(const std::string& id) const {
    auto it = id_to_idx_.find(id);
    if (it == id_to_idx_.end()) return nullptr;
    return &nodes_[it->second];
}

std::vector<std::string> TrustGraph::neighbors(const std::string& id) const {
    auto it = adj_.find(id);
    if (it == adj_.end()) return {};
    return it->second;
}

// ── Reachability (DFS) ────────────────────────────────────────────────────────

std::unordered_set<std::string> TrustGraph::reachable_from(const std::string& start) const {
    std::unordered_set<std::string> visited;
    std::vector<std::string> stack = {start};

    while (!stack.empty()) {
        std::string cur = stack.back(); stack.pop_back();
        if (!visited.insert(cur).second) continue;
        for (auto& nb : neighbors(cur))
            stack.push_back(nb);
    }
    return visited;
}

// ── Permission closure ────────────────────────────────────────────────────────
// Walks DependsOn edges (transitive deps) then Grants edges to permissions

std::unordered_set<std::string> TrustGraph::permission_closure(const std::string& ext_id) const {
    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> perms;
    // (node_id, is_already_in_perm_phase)
    std::vector<std::pair<std::string, bool>> stack = {{ext_id, false}};

    while (!stack.empty()) {
        auto [node, is_perm] = stack.back(); stack.pop_back();
        if (!visited.insert(node).second) continue;

        if (is_perm) {
            perms.insert(node);
            continue;
        }

        for (auto& edge : edges_) {
            if (edge.from != node) continue;
            switch (edge.kind) {
                case EdgeKind::Grants:
                    stack.push_back({edge.to, true});
                    break;
                case EdgeKind::DependsOn:
                    stack.push_back({edge.to, false});
                    break;
                default:
                    break;
            }
        }
    }
    return perms;
}

// ── Tarjan SCC ────────────────────────────────────────────────────────────────

void TrustGraph::tarjan_dfs(
    const std::string& v,
    std::unordered_map<std::string, int>& index,
    std::unordered_map<std::string, int>& lowlink,
    std::unordered_map<std::string, bool>& on_stack,
    std::vector<std::string>& stack,
    int& idx_counter,
    std::vector<std::vector<std::string>>& sccs) const
{
    index[v] = lowlink[v] = idx_counter++;
    stack.push_back(v);
    on_stack[v] = true;

    for (auto& nb : neighbors(v)) {
        if (!index.count(nb)) {
            tarjan_dfs(nb, index, lowlink, on_stack, stack, idx_counter, sccs);
            lowlink[v] = std::min(lowlink[v], lowlink[nb]);
        } else if (on_stack.count(nb) && on_stack.at(nb)) {
            lowlink[v] = std::min(lowlink[v], index[nb]);
        }
    }

    if (lowlink[v] == index[v]) {
        std::vector<std::string> scc;
        while (true) {
            std::string w = stack.back(); stack.pop_back();
            on_stack[w] = false;
            scc.push_back(w);
            if (w == v) break;
        }
        if (scc.size() > 1) sccs.push_back(std::move(scc));
    }
}

std::vector<std::vector<std::string>> TrustGraph::detect_cycles() const {
    std::unordered_map<std::string, int>  index, lowlink;
    std::unordered_map<std::string, bool> on_stack;
    std::vector<std::string> stack;
    std::vector<std::vector<std::string>> sccs;
    int idx_counter = 0;

    for (auto& node : nodes_) {
        if (!index.count(node.id))
            tarjan_dfs(node.id, index, lowlink, on_stack, stack, idx_counter, sccs);
    }
    return sccs;
}

// ── Betweenness centrality (BFS-based approximation) ─────────────────────────
// Simplified: score = number of shortest paths passing through each node

std::vector<std::string> TrustGraph::top_central_nodes(int n) const {
    std::unordered_map<std::string, double> centrality;
    for (auto& node : nodes_) centrality[node.id] = 0.0;

    for (auto& source : nodes_) {
        // BFS from source
        std::unordered_map<std::string, double> sigma;  // # shortest paths
        std::unordered_map<std::string, double> delta;  // dependency
        std::unordered_map<std::string, int>    dist;
        std::unordered_map<std::string, std::vector<std::string>> pred;
        std::queue<std::string> q;
        std::vector<std::string> order;

        sigma[source.id] = 1.0;
        dist[source.id]  = 0;
        q.push(source.id);

        while (!q.empty()) {
            std::string v = q.front(); q.pop();
            order.push_back(v);
            for (auto& w : neighbors(v)) {
                if (!dist.count(w)) {
                    dist[w] = dist[v] + 1;
                    q.push(w);
                }
                if (dist[w] == dist[v] + 1) {
                    sigma[w] += sigma[v];
                    pred[w].push_back(v);
                }
            }
        }

        // Back-propagation
        for (auto& v : order) delta[v] = 0.0;
        while (!order.empty()) {
            std::string w = order.back(); order.pop_back();
            for (auto& v : pred[w]) {
                delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w]);
            }
            if (w != source.id) centrality[w] += delta[w];
        }
    }

    // Sort by centrality desc
    std::vector<std::pair<double, std::string>> ranked;
    for (auto& [id, c] : centrality) ranked.push_back({c, id});
    std::sort(ranked.rbegin(), ranked.rend());

    std::vector<std::string> result;
    for (int i = 0; i < n && i < (int)ranked.size(); ++i)
        result.push_back(ranked[i].second);
    return result;
}

// ── Risk propagation ──────────────────────────────────────────────────────────

void TrustGraph::propagate_risk() {
    // Simple: a node inherits the max risk score of nodes it reaches
    for (auto& node : nodes_) {
        auto reachable = reachable_from(node.id);
        for (auto& rid : reachable) {
            auto* rn = get_node(rid);
            if (rn && rn->risk_score > node.risk_score) {
                nodes_[id_to_idx_[node.id]].risk_score = rn->risk_score * 0.8;
            }
        }
    }
}

// ── to_text ───────────────────────────────────────────────────────────────────

std::string TrustGraph::to_text() const {
    std::ostringstream ss;
    ss << "=== Trust Graph ===\n";
    ss << "Nodes: " << nodes_.size() << "  Edges: " << edges_.size() << "\n\n";

    for (auto& node : nodes_) {
        ss << "[" << node.id << "] " << node.label
           << " (" << severity_str(node.severity) << ", score=" << node.risk_score << ")\n";
        for (auto& edge : edges_) {
            if (edge.from != node.id) continue;
            ss << "  ─→ " << edge.to << " (" << edge.label << ")\n";
        }
    }
    return ss.str();
}

// ── build_trust_graph ─────────────────────────────────────────────────────────

TrustGraph build_trust_graph(const std::vector<Finding>& findings) {
    TrustGraph g;

    // Root system node
    GraphNode sys;
    sys.id = "system";
    sys.kind = NodeKind::System;
    sys.label = "system";
    sys.risk_score = 0.0;
    g.add_node(sys);

    for (auto& f : findings) {
        // Derive a stable node ID from the file path
        std::string node_id = "file:" + f.file;

        // Determine node kind from rule prefix
        NodeKind kind = NodeKind::File;
        if (f.rule_id.substr(0, 3) == "EXT") kind = NodeKind::Extension;
        else if (f.rule_id.substr(0, 3) == "NPM") kind = NodeKind::Package;
        else if (f.rule_id.substr(0, 4) == "PROC") kind = NodeKind::Process;
        else if (f.rule_id.substr(0, 3) == "SEC") kind = NodeKind::File;
        else if (f.rule_id.substr(0, 6) == "DOCKER") kind = NodeKind::Package;

        // Short label from last path component
        std::string label = std::filesystem::path(f.file).filename().string();

        GraphNode node;
        node.id         = node_id;
        node.kind       = kind;
        node.label      = label;
        node.risk_score = f.score;
        node.severity   = f.severity;
        g.add_node(node);

        // Edge: system → finding node (or update existing node's risk)
        GraphEdge edge;
        edge.from   = "system";
        edge.to     = node_id;
        edge.kind   = EdgeKind::Accesses;
        edge.weight = f.score;
        edge.label  = f.rule_id;
        g.add_edge(edge);

        // For secret findings, add a "contains_secret" edge
        if (f.rule_id.substr(0, 3) == "SEC") {
            GraphEdge se;
            se.from   = node_id;
            se.to     = "secrets:pool";
            se.kind   = EdgeKind::ContainsSecret;
            se.weight = f.score;
            se.label  = f.message.empty() ? f.rule_id : f.message;
            g.add_edge(se);
        }
    }

    // Ensure secrets pool exists
    if (!g.has_node("secrets:pool")) {
        GraphNode sp;
        sp.id = "secrets:pool";
        sp.kind = NodeKind::File;
        sp.label = "secrets";
        g.add_node(sp);
    }

    g.propagate_risk();
    return g;
}

// ── compute_trust_score ───────────────────────────────────────────────────────
//
// Scoring philosophy:
//   - File/secret findings are the primary signal (credentials, secrets, configs)
//   - Process findings are secondary: only AI tool findings (PROC-003/004) carry
//     the same weight as file findings; generic root-process findings (PROC-002)
//     are minimal noise so they barely affect score
//   - One leaked AWS key should score ~30. Ten medium proc findings should not
//     tank a clean system to 0.
//
// Scale: 100 = clean, 0 = fully compromised
//
// Penalty breakdown (max 100):
//   File/secret findings:
//     - Worst single file/secret critical: up to -45
//     - Additional crits (diminishing):    up to -25
//     - High file findings (diminishing):  up to -15
//   Process findings:
//     - AI tool reading secrets (PROC-004): up to -10
//     - Dangerous caps (PROC-001):          up to -5
//     - Generic root/seccomp (PROC-002):    capped at -5 total regardless of count

int compute_trust_score(const TrustGraph& g) {
    if (g.node_count() <= 1) return 100;

    double file_max_crit  = 0.0;  // worst single file/secret/ext/docker finding
    int    file_crit_cnt  = 0;
    int    file_high_cnt  = 0;

    double ai_proc_max    = 0.0;  // PROC-003/PROC-004 (AI with sensitive FDs)
    double cap_proc_max   = 0.0;  // PROC-001 (dangerous caps on user process)
    int    noise_proc_cnt = 0;    // PROC-002 generic root/seccomp noise

    for (auto& node : g.nodes()) {
        if (node.id == "system" || node.id == "secrets:pool") continue;

        // Classify by rule prefix embedded in node id or severity
        bool is_proc002 = (node.id.find("/proc/") != std::string::npos &&
                           node.severity == Severity::Medium);
        bool is_proc_ai = (node.id.find("/proc/") != std::string::npos &&
                           node.severity == Severity::Critical);
        bool is_proc_cap= (node.id.find("/proc/") != std::string::npos &&
                           node.severity == Severity::High);

        if (is_proc002) {
            ++noise_proc_cnt;
        } else if (is_proc_ai) {
            ai_proc_max = std::max(ai_proc_max, node.risk_score);
        } else if (is_proc_cap) {
            cap_proc_max = std::max(cap_proc_max, node.risk_score);
        } else {
            // File / secret / extension / npm / docker finding
            if (node.severity == Severity::Critical) {
                file_max_crit = std::max(file_max_crit, node.risk_score);
                ++file_crit_cnt;
            } else if (node.severity == Severity::High) {
                ++file_high_cnt;
            }
        }
    }

    double penalty = 0.0;

    // File/secret component
    penalty += file_max_crit * 4.5;                         // worst crit: up to -42.75 (9.5*4.5)
    penalty += std::min((file_crit_cnt - (file_max_crit > 0 ? 1 : 0)) * 4.0, 25.0); // more crits
    penalty += std::min(file_high_cnt * 2.0, 15.0);         // high file findings

    // Process component
    penalty += std::min(ai_proc_max * 1.0,  10.0);          // AI proc findings
    penalty += std::min(cap_proc_max * 0.5,  5.0);          // dangerous caps
    penalty += std::min(noise_proc_cnt * 0.1, 5.0);         // root/seccomp noise: max -5

    int score = 100 - static_cast<int>(std::min(penalty, 100.0));
    return std::max(0, score);
}

} // namespace overtrust
