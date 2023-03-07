// SPDX-FileCopyrightText: Copyright 2018 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <array>
#include <chrono>
#include <cryptopp/osrng.h>

#include "common/logging/log.h"
#include "common/string_util.h"
#include "core/core.h"
#include "core/hle/service/nfc/amiibo_crypto.h"
#include "core/hle/service/nfc/nfc_device.h"

namespace Service::NFC {
NfcDevice::NfcDevice(Core::System& system) {
    tag_in_range_event =
        system.Kernel().CreateEvent(Kernel::ResetType::OneShot, "NFC::tag_in_range_event");
    tag_out_of_range_event =
        system.Kernel().CreateEvent(Kernel::ResetType::OneShot, "NFC::tag_out_range_event");
}

NfcDevice::~NfcDevice() = default;

bool NfcDevice::LoadAmiibo(const EncryptedNTAG215File& data) {
    if (device_state != DeviceState::SearchingForTag) {
        LOG_ERROR(Service_NFC, "Game is not looking for amiibos, current state {}", device_state);
        return false;
    }

    // TODO: Filter by allowed_protocols here

    encrypted_tag_data = data;

    device_state = DeviceState::TagFound;
    tag_out_of_range_event->Clear();
    tag_in_range_event->Signal();
    return true;
}

void NfcDevice::CloseAmiibo() {
    LOG_INFO(Service_NFC, "Remove amiibo");

    if (device_state == DeviceState::TagMounted) {
        Unmount();
    }

    device_state = DeviceState::TagRemoved;
    encrypted_tag_data = {};
    tag_data = {};
    tag_in_range_event->Clear();
    tag_out_of_range_event->Signal();
}

std::shared_ptr<Kernel::Event> NfcDevice::GetActivateEvent() const {
    return tag_in_range_event;
}

std::shared_ptr<Kernel::Event> NfcDevice::GetDeactivateEvent() const {
    return tag_out_of_range_event;
}

void NfcDevice::Initialize() {
    device_state = DeviceState::Initialized;
    encrypted_tag_data = {};
    tag_data = {};
}

void NfcDevice::Finalize() {
    if (device_state == DeviceState::TagMounted) {
        Unmount();
    }
    if (device_state == DeviceState::SearchingForTag || device_state == DeviceState::TagRemoved) {
        StopDetection();
    }
    device_state = DeviceState::NotInitialized;
}

ResultCode NfcDevice::StartDetection(TagProtocol allowed_protocol) {
    if (device_state != DeviceState::Initialized && device_state != DeviceState::TagRemoved) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        return WrongDeviceState;
    }

    // TODO: Set console in search mode here

    device_state = DeviceState::SearchingForTag;
    allowed_protocols = allowed_protocol;
    return RESULT_SUCCESS;
}

ResultCode NfcDevice::StopDetection() {
    // TODO: Stop console search mode here

    if (device_state == DeviceState::Initialized) {
        return RESULT_SUCCESS;
    }

    if (device_state == DeviceState::TagFound || device_state == DeviceState::TagMounted) {
        CloseAmiibo();
        return RESULT_SUCCESS;
    }
    if (device_state == DeviceState::SearchingForTag || device_state == DeviceState::TagRemoved) {
        device_state = DeviceState::Initialized;
        return RESULT_SUCCESS;
    }

    LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
    return WrongDeviceState;
}

ResultCode NfcDevice::Flush() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    auto& settings = tag_data.settings;

    const auto& current_date = GetAmiiboDate();
    if (settings.write_date.raw_date != current_date.raw_date) {
        settings.write_date = current_date;
        settings.crc_counter++;
        // TODO: Find how to calculate the crc check
        // settings.crc = CalculateCRC(settings);
    }

    tag_data.write_counter++;

    if (!AmiiboCrypto::EncodeAmiibo(tag_data, encrypted_tag_data)) {
        LOG_ERROR(Service_NFC, "Failed to encode data");
        return WriteAmiiboFailed;
    }

    std::vector<u8> data(sizeof(encrypted_tag_data));
    memcpy(data.data(), &encrypted_tag_data, sizeof(encrypted_tag_data));

    // TODO: Write data to file here on failure return WriteAmiiboFailed

    is_data_moddified = false;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::Mount(MountTarget mount_target_) {
    if (device_state != DeviceState::TagFound) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        return WrongDeviceState;
    }

    if (!AmiiboCrypto::IsAmiiboValid(encrypted_tag_data)) {
        LOG_ERROR(Service_NFC, "Not an amiibo");
        return NotAnAmiibo;
    }

    // Mark amiibos as read only when keys are missing
    if (!AmiiboCrypto::IsKeyAvailable()) {
        LOG_ERROR(Service_NFC, "No keys detected");
        device_state = DeviceState::TagMounted;
        mount_target = MountTarget::Rom;
        return RESULT_SUCCESS;
    }

    if (!AmiiboCrypto::DecodeAmiibo(encrypted_tag_data, tag_data)) {
        LOG_ERROR(Service_NFC, "Can't decode amiibo {}", device_state);
        return CorruptedData;
    }

    device_state = DeviceState::TagMounted;
    mount_target = mount_target_;
    return RESULT_SUCCESS;
}

ResultCode NfcDevice::Unmount() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    // Save data before unloading the amiibo
    if (is_data_moddified) {
        Flush();
    }

    device_state = DeviceState::TagFound;
    mount_target = MountTarget::None;
    is_app_area_open = false;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetTagInfo2(TagInfo2& tag_info) const {
    if (device_state != DeviceState::TagFound && device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    tag_info = {
        .uuid_length = static_cast<u16>(encrypted_tag_data.uuid.uid.size()),
        .tag_type = PackedTagType::Type2,
        .uuid = encrypted_tag_data.uuid.uid,
        .extra_data = {}, // Used on non amiibo tags
        .protocol = TagProtocol::None,
        .extra_data2 = {}, // Used on non amiibo tags
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetTagInfo(TagInfo& tag_info) const {
    if (device_state != DeviceState::TagFound && device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    tag_info = {
        .uuid_length = static_cast<u16>(encrypted_tag_data.uuid.uid.size()),
        .protocol = PackedTagProtocol::None,
        .tag_type = PackedTagType::Type2,
        .uuid = encrypted_tag_data.uuid.uid,
        .extra_data = {}, // Used on non amiibo tags
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetAmiiboConfig(AmiiboConfig& common_info) const {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    const auto& settings = tag_data.settings;
    const auto& model_info_data = tag_data.model_info;

    // TODO: Validate this data
    common_info = {
        .last_write_date = settings.write_date.GetWriteDate(),
        .write_counter = tag_data.write_counter,
        .version = 0,
        .application_area_size = sizeof(ApplicationArea),
    };

    static_assert(sizeof(AmiiboConfig) == 0x40, "CommonInfo is an invalid size");
    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetModelInfo(ModelInfo& model_info) const {
    if (device_state != DeviceState::TagFound && device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    const auto& model_info_data = encrypted_tag_data.user_memory.model_info;
    model_info = {
        .character_id = model_info_data.character_id,
        .character_variant = model_info_data.character_variant,
        .series = model_info_data.series,
        .model_number = model_info_data.model_number,
        .amiibo_type = model_info_data.amiibo_type,
    };
    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetSettingInfo(SettingsInfo& settings_info) const {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    if (tag_data.settings.settings.amiibo_initialized == 0) {
        return RegistrationIsNotInitialized;
    }

    const auto& settings = tag_data.settings;

    // TODO: Validate this data
    settings_info = {
        .mii_data = tag_data.owner_mii,
        .mii_data_aes_ccm = tag_data.owner_mii_aes_ccm,
        .amiibo_name = GetAmiiboName(settings),
        .flags = settings.settings,
        .font_region = settings.country_code_id,
        .creation_date = settings.init_date.GetWriteDate(),
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::SetNicknameAndOwner(const AmiiboName& amiibo_name) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    auto& settings = tag_data.settings;

    settings.init_date = GetAmiiboDate();
    settings.write_date = GetAmiiboDate();
    settings.crc_counter++;
    // TODO: Find how to calculate the crc check
    // settings.crc = CalculateCRC(settings);

    // TODO: Calculate mii checksum
    // tag_data.owner_mii_aes_ccm = ? ? ? ? ;

    SetAmiiboName(settings, amiibo_name);
    tag_data.owner_mii = HLE::Applets::MiiSelector::GetStandardMiiResult().selected_mii_data;
    settings.settings.amiibo_initialized.Assign(1);

    return Flush();
}

ResultCode NfcDevice::RestoreAmiibo() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    // TODO: Load amiibo from backup on system
    LOG_ERROR(Service_NFC, "Not Implemented");
    return RESULT_SUCCESS;
}

ResultCode NfcDevice::DeleteAllData() {
    const auto ResultCode = DeleteApplicationArea();
    if (ResultCode.IsError()) {
        return ResultCode;
    }

    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    CryptoPP::AutoSeededRandomPool rng;
    const std::size_t data_size = sizeof(tag_data.owner_mii);
    std::array<CryptoPP::byte, data_size> buffer{};
    rng.GenerateBlock(buffer.data(), data_size);
    memcpy(&tag_data.owner_mii, buffer.data(), data_size);
    tag_data.settings.settings.amiibo_initialized.Assign(0);

    return Flush();
}

ResultCode NfcDevice::OpenApplicationArea(u32 access_id) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    if (tag_data.settings.settings.appdata_initialized.Value() == 0) {
        LOG_WARNING(Service_NFC, "Application area is not initialized");
        return ApplicationAreaIsNotInitialized;
    }

    if (tag_data.application_area_id != access_id) {
        LOG_WARNING(Service_NFC, "Wrong application area id");
        return WrongApplicationAreaId;
    }

    is_app_area_open = true;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetApplicationAreaId(u32& application_area_id) const {
    application_area_id = {};

    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    if (tag_data.settings.settings.appdata_initialized.Value() == 0) {
        LOG_WARNING(Service_NFC, "Application area is not initialized");
        return ApplicationAreaIsNotInitialized;
    }

    application_area_id = tag_data.application_area_id;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetApplicationArea(std::vector<u8>& data) const {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    if (!is_app_area_open) {
        LOG_ERROR(Service_NFC, "Application area is not open");
        return WrongDeviceState;
    }

    if (tag_data.settings.settings.appdata_initialized.Value() == 0) {
        LOG_ERROR(Service_NFC, "Application area is not initialized");
        return ApplicationAreaIsNotInitialized;
    }

    if (data.size() > sizeof(ApplicationArea)) {
        data.resize(sizeof(ApplicationArea));
    }

    memcpy(data.data(), tag_data.application_area.data(), data.size());

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::SetApplicationArea(std::span<const u8> data) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    if (!is_app_area_open) {
        LOG_ERROR(Service_NFC, "Application area is not open");
        return WrongDeviceState;
    }

    if (tag_data.settings.settings.appdata_initialized.Value() == 0) {
        LOG_ERROR(Service_NFC, "Application area is not initialized");
        return ApplicationAreaIsNotInitialized;
    }

    if (data.size() > sizeof(ApplicationArea)) {
        LOG_ERROR(Service_NFC, "Wrong data size {}", data.size());
        return WrongDeviceState;
    }

    std::memcpy(tag_data.application_area.data(), data.data(), data.size());

    // Fill remaining data with random numbers
    CryptoPP::AutoSeededRandomPool rng;
    const std::size_t data_size = sizeof(ApplicationArea) - data.size();
    std::vector<CryptoPP::byte> buffer(data_size);
    rng.GenerateBlock(buffer.data(), data_size);
    memcpy(tag_data.application_area.data() + data.size(), buffer.data(), data_size);

    tag_data.applicaton_write_counter++;
    is_data_moddified = true;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::CreateApplicationArea(u32 access_id, std::span<const u8> data) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (tag_data.settings.settings.appdata_initialized.Value() != 0) {
        LOG_ERROR(Service_NFC, "Application area already exist");
        return ApplicationAreaExist;
    }

    return RecreateApplicationArea(access_id, data);
}

ResultCode NfcDevice::RecreateApplicationArea(u32 access_id, std::span<const u8> data) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    if (data.size() > sizeof(ApplicationArea)) {
        LOG_ERROR(Service_NFC, "Wrong data size {}", data.size());
        return WrongApplicationAreaSize;
    }

    std::memcpy(tag_data.application_area.data(), data.data(), data.size());

    // Fill remaining data with random numbers
    CryptoPP::AutoSeededRandomPool rng;
    const std::size_t data_size = sizeof(ApplicationArea) - data.size();
    std::vector<CryptoPP::byte> buffer(data_size);
    rng.GenerateBlock(buffer.data(), data_size);
    memcpy(tag_data.application_area.data() + data.size(), buffer.data(), data_size);

    // TODO: Investigate why the title id needs to be moddified
    // tag_data.title_id = system.GetApplicationProcessProgramID();
    // tag_data.title_id = tag_data.title_id | 0x30000000ULL;
    tag_data.settings.settings.appdata_initialized.Assign(1);
    tag_data.application_area_id = access_id;
    tag_data.applicaton_write_counter++;
    tag_data.unknown = {};

    return Flush();
}

ResultCode NfcDevice::DeleteApplicationArea() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return TagRemoved;
        }
        return WrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return WrongDeviceState;
    }

    CryptoPP::AutoSeededRandomPool rng;
    constexpr std::size_t data_size = sizeof(ApplicationArea);
    std::array<CryptoPP::byte, data_size> buffer{};
    rng.GenerateBlock(buffer.data(), data_size);

    // Reset data with random bytes
    memcpy(tag_data.application_area.data(), buffer.data(), data_size);
    memcpy(&tag_data.title_id, buffer.data(), sizeof(u64));
    tag_data.application_area_id = rng.GenerateWord32();
    tag_data.settings.settings.appdata_initialized.Assign(0);
    tag_data.applicaton_write_counter++;
    tag_data.unknown = {};

    return Flush();
}

u32 NfcDevice::GetApplicationAreaSize() const {
    return sizeof(ApplicationArea);
}

DeviceState NfcDevice::GetCurrentState() const {
    return device_state;
}

AmiiboName NfcDevice::GetAmiiboName(const AmiiboSettings& settings) const {
    std::array<char16_t, amiibo_name_length> settings_amiibo_name{};
    AmiiboName amiibo_name{};

    // Convert from big endian to little endian
    for (std::size_t i = 0; i < amiibo_name_length; i++) {
        amiibo_name[i] = static_cast<u16>(settings.amiibo_name[i]);
    }

    return amiibo_name;
}

void NfcDevice::SetAmiiboName(AmiiboSettings& settings, const AmiiboName& amiibo_name) {
    std::array<char16_t, amiibo_name_length> settings_amiibo_name{};

    // Convert from little endian to big endian
    for (std::size_t i = 0; i < amiibo_name_length; i++) {
        settings.amiibo_name[i] = static_cast<u16_be>(amiibo_name[i]);
    }
}

AmiiboDate NfcDevice::GetAmiiboDate() const {
    const auto now = std::chrono::system_clock::now();
    time_t time = std::chrono::system_clock::to_time_t(now);
    tm local_tm = *localtime(&time);
    AmiiboDate amiibo_date{};

    amiibo_date.SetYear(static_cast<u16>(local_tm.tm_year));
    amiibo_date.SetMonth(static_cast<u8>(local_tm.tm_mon));
    amiibo_date.SetDay(static_cast<u8>(local_tm.tm_mday));

    return amiibo_date;
}

} // namespace Service::NFC
