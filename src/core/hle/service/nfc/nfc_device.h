// SPDX-FileCopyrightText: Copyright 2018 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <span>
#include <vector>

#include "common/common_types.h"
#include "core/hle/service/nfc/nfc_results.h"
#include "core/hle/service/nfc/nfc_types.h"
#include "core/hle/service/service.h"

namespace Kernel {
class KEvent;
class KReadableEvent;
} // namespace Kernel

namespace Service::NFC {
class NfcDevice {
public:
    NfcDevice(Core::System& system);
    ~NfcDevice();

    bool LoadAmiibo(std::string amiibo_filename_);
    void CloseAmiibo();

    void Initialize();
    void Finalize();

    ResultCode StartDetection(TagProtocol allowed_protocol);
    ResultCode StopDetection();
    ResultCode Mount(MountTarget mount_target);
    ResultCode Unmount();
    ResultCode Flush();

    ResultCode GetTagInfo2(TagInfo2& tag_info) const;
    ResultCode GetTagInfo(TagInfo& tag_info) const;
    ResultCode GetAmiiboConfig(AmiiboConfig& common_info) const;
    ResultCode GetModelInfo(ModelInfo& model_info) const;
    ResultCode GetSettingInfo(SettingsInfo& settings_info) const;

    ResultCode SetNicknameAndOwner(const AmiiboName& amiibo_name);
    ResultCode RestoreAmiibo();
    ResultCode DeleteAllData();

    ResultCode OpenApplicationArea(u32 access_id);
    ResultCode GetApplicationAreaId(u32& application_area_id) const;
    ResultCode GetApplicationArea(std::vector<u8>& data) const;
    ResultCode SetApplicationArea(std::span<const u8> data);
    ResultCode CreateApplicationArea(u32 access_id, std::span<const u8> data);
    ResultCode RecreateApplicationArea(u32 access_id, std::span<const u8> data);
    ResultCode DeleteApplicationArea();

    u32 GetApplicationAreaSize() const;
    DeviceState GetCurrentState() const;

    std::shared_ptr<Kernel::Event> GetActivateEvent() const;
    std::shared_ptr<Kernel::Event> GetDeactivateEvent() const;

private:
    AmiiboName GetAmiiboName(const AmiiboSettings& settings) const;
    void SetAmiiboName(AmiiboSettings& settings, const AmiiboName& amiibo_name);
    AmiiboDate GetAmiiboDate() const;

    std::shared_ptr<Kernel::Event> tag_in_range_event = nullptr;
    std::shared_ptr<Kernel::Event> tag_out_of_range_event = nullptr;

    bool is_data_moddified{};
    bool is_app_area_open{};
    TagProtocol allowed_protocols{};
    MountTarget mount_target{MountTarget::None};
    DeviceState device_state{DeviceState::NotInitialized};

    std::string amiibo_filename = "";

    NTAG215File tag_data{};
    EncryptedNTAG215File encrypted_tag_data{};
};

} // namespace Service::NFC
