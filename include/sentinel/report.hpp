#pragma once

#include <string>
#include <vector>
#include "sentinel/types.hpp"
#include "sentinel/graph.hpp"

namespace sentinel {

// Serialize findings + graph to a JSON report file
bool write_json_report(const std::string& output_path,
                       const std::vector<Finding>& findings,
                       const TrustGraph& graph,
                       int trust_score,
                       const std::string& target);

} // namespace sentinel
