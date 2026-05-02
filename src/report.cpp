#include "overtrust/report.hpp"

#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <nlohmann/json.hpp>

namespace overtrust {

using json = nlohmann::json;

static std::string iso8601_now() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static const char* severity_json(Severity s) {
    switch (s) {
        case Severity::Critical: return "critical";
        case Severity::High:     return "high";
        case Severity::Medium:   return "medium";
        case Severity::Low:      return "low";
        default:                 return "info";
    }
}

bool write_json_report(const std::string& output_path,
                       const std::vector<Finding>& findings,
                       const TrustGraph& graph,
                       int trust_score,
                       const std::string& target)
{
    json report;
    report["sentinel_version"] = "0.1.0";
    report["timestamp"]        = iso8601_now();
    report["target"]           = target;
    report["trust_score"]      = trust_score;

    // Summary
    int crit=0, high=0, med=0, low=0, info=0;
    for (auto& f : findings) {
        switch (f.severity) {
            case Severity::Critical: ++crit; break;
            case Severity::High:     ++high; break;
            case Severity::Medium:   ++med;  break;
            case Severity::Low:      ++low;  break;
            default:                 ++info; break;
        }
    }
    report["summary"] = {
        {"total_findings", findings.size()},
        {"critical",       crit},
        {"high",           high},
        {"medium",         med},
        {"low",            low},
        {"info",           info},
        {"graph_nodes",    graph.node_count()},
        {"graph_edges",    graph.edge_count()},
    };

    // Findings array
    json jfindings = json::array();
    for (auto& f : findings) {
        jfindings.push_back({
            {"id",       f.id},
            {"rule",     f.rule_id},
            {"severity", severity_json(f.severity)},
            {"file",     f.file},
            {"message",  f.message},
            {"score",    f.score},
            {"evidence", f.evidence},
        });
    }
    report["findings"] = jfindings;

    // Graph nodes (abbreviated)
    json jnodes = json::array();
    for (auto& n : graph.nodes()) {
        jnodes.push_back({
            {"id",    n.id},
            {"label", n.label},
            {"risk",  n.risk_score},
        });
    }
    report["graph"]["nodes"] = jnodes;

    // Graph edges
    json jedges = json::array();
    for (auto& e : graph.edges()) {
        jedges.push_back({
            {"from",  e.from},
            {"to",    e.to},
            {"label", e.label},
        });
    }
    report["graph"]["edges"] = jedges;

    std::ofstream f(output_path);
    if (!f) return false;
    f << report.dump(2);
    return true;
}

} // namespace overtrust
