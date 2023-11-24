/*
// Copyright (c) 2022 Intel Corporation
//
// This software and the related documents are Intel copyrighted
// materials, and your use of them is governed by the express license
// under which they were provided to you ("License"). Unless the
// License provides otherwise, you may not use, modify, copy, publish,
// distribute, disclose or transmit this software or the related
// documents without Intel's prior written permission.
//
// This software and the related documents are provided as is, with no
// express or implied warranties, other than those that are expressly
// stated in the License.
*/
#pragma once

#include "spdmapplib.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <vector>

using json = nlohmann::json;

class SPDMConfigReader
{
  public:
    SPDMConfigReader() = delete;
    SPDMConfigReader(const SPDMConfigReader&) = delete;
    SPDMConfigReader& operator=(const SPDMConfigReader&) = delete;
    SPDMConfigReader(SPDMConfigReader&&) = delete;
    SPDMConfigReader& operator=(SPDMConfigReader&&) = delete;
    explicit SPDMConfigReader(spdm_app_lib::SPDMConfiguration& spdmCfgData);
  private:
    void readSPDMConfig();
    void parseSPDMConfig();
    bool computeSPDMConfig(spdm_app_lib::SPDMConfiguration& spdmCfgData);
    bool getSPDMConfigData(
        uint32_t& spdmConfig, std::vector<std::string>& spdmUserConfig,
        const std::map<std::string, uint32_t>& spdmConfigVerifier);
    bool getValueFromName(const std::map<std::string, uint32_t>& table,
                          std::string name, uint32_t& value);
    std::vector<std::string> configValue(json& values);
    json configData = nullptr;
    const std::string configPath =
        "/usr/share/spdmd/configurations/spdm_responder_config.json";
    std::ifstream configFile;
};
