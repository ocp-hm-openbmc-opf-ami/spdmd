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

#include "spdm_config_reader.hpp"

#include <phosphor-logging/log.hpp>

#include <filesystem>
#include <iostream>

SPDMConfigReader::SPDMConfigReader(spdm_app_lib::SPDMConfiguration& spdmCfgData)
{
    readSPDMConfig();
    parseSPDMConfig();
    computeSPDMConfig(spdmCfgData);
}

void SPDMConfigReader::readSPDMConfig()
{
    if (!std::filesystem::exists(configPath.c_str()))
    {
        throw std::runtime_error("SPDM Config does not exists");
    }
    configFile.open(configPath.c_str());
    if (!configFile.good())
    {
        throw std::runtime_error("Error opening");
    }
}

void SPDMConfigReader::parseSPDMConfig()
{
    try
    {
        configData = json::parse(configFile, nullptr, false);
        if (configData.is_discarded())
        {
            phosphor::logging::log<phosphor::logging::level::WARNING>(
                "Error parsing SPDM Config");
        }
    }
    catch (json::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Error Parsing of the Config: ") + e.what()).c_str());
    }
    configFile.close();
}

std::vector<std::string> SPDMConfigReader::configValue(json& value)
{
    std::vector<std::string> data;
    /* Converting json to vector */
    std::transform(value.begin(), value.end(), std::back_inserter(data),
                   [](const auto& e) { return e; });
    return data;
}

bool SPDMConfigReader::computeSPDMConfig(
    spdm_app_lib::SPDMConfiguration& spdmResponderCfg)
{
    try
    {
        auto data = configValue(configData["Version"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.version, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::version)))
        {
            return false;
        }
        data = configValue(configData["Capability"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.capability, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::responderCaps)))
        {
            return false;
        }
        data = configValue(configData["Hash"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.hash, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::baseHash)))
        {
            return false;
        }
        data = configValue(configData["MeasHash"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.measHash, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::measHash)))
        {
            return false;
        }
        data = configValue(configData["Asym"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.asym, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::asymHash)))
        {
            return false;
        }
        data = configValue(configData["ReqAsym"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.reqasym, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::asymHash)))
        {
            return false;
        }
        data = configValue(configData["Dhe"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.dhe, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::dheValue)))
        {
            return false;
        }
        data = configValue(configData["Aead"]);
        if (!getSPDMConfigData(
                spdmResponderCfg.aead, data,
                spdm_app_lib::getSPDMConfigMap(
                    spdm_app_lib::SPDMConfigIdentifier::aeadValue)))
        {
            return false;
        }
        spdmResponderCfg.slotcount =
            static_cast<uint32_t>(configData["SlotCount"]);
        spdmResponderCfg.certPath =
            static_cast<std::string>(configData["CertPath"]);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Error Parsing of the Config: ") + e.what()).c_str());
    }
    return true;
}

bool SPDMConfigReader::getSPDMConfigData(
    uint32_t& spdmConfig, std::vector<std::string>& spdmUserConfig,
    const std::map<std::string, uint32_t>& spdmConfigVerifier)
{
    uint32_t spdmConfigData;
    for (std::string& entry : spdmUserConfig)
    {
        spdmConfigData = 0;

        if (!getValueFromName(spdmConfigVerifier, entry, spdmConfigData))
        {
            spdmUserConfig.clear();
            return false;
        }
        spdmConfig = spdmConfig | spdmConfigData;
    }
    spdmUserConfig.clear();
    return true;
}

bool SPDMConfigReader::getValueFromName(
    const std::map<std::string, uint32_t>& table, std::string name,
    uint32_t& value)
{
    auto item = table.find(name);

    if (item == table.end())
    {
        return false;
    }
    // actions when found
    value = item->second;
    return true;
}
