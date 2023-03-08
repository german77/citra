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

SERVICE_CONSTRUCT_IMPL(Service::NFC::NfcDevice)

namespace Service::NFC {
template <class Archive>
void NfcDevice::serialize(Archive& ar, const unsigned int) {
    ar& tag_in_range_event;
    ar& tag_out_of_range_event;
    ar& is_data_moddified;
    ar& is_app_area_open;
    ar& allowed_protocols;
    ar& mount_target;
    ar& device_state;
    ar& amiibo_filename;
    ar& tag;
    ar& encrypted_tag;
}
SERIALIZE_IMPL(NfcDevice)

NfcDevice::NfcDevice(Core::System& system) {
    tag_in_range_event =
        system.Kernel().CreateEvent(Kernel::ResetType::OneShot, "NFC::tag_in_range_event");
    tag_out_of_range_event =
        system.Kernel().CreateEvent(Kernel::ResetType::OneShot, "NFC::tag_out_range_event");
}

NfcDevice::~NfcDevice() = default;

bool NfcDevice::LoadAmiibo(std::string amiibo_filename_) {
    FileUtil::IOFile amiibo_file(amiibo_filename_, "rb");

    if (device_state != DeviceState::SearchingForTag) {
        LOG_ERROR(Service_NFC, "Game is not looking for amiibos, current state {}", device_state);
        return false;
    }

    if (!amiibo_file.IsOpen()) {
        LOG_ERROR(Service_NFC, "Could not open amiibo file \"{}\"", amiibo_filename_);
        return false;
    }

    if (!amiibo_file.ReadBytes(&encrypted_tag.file, sizeof(encrypted_tag.file))) {
        LOG_ERROR(Service_NFC, "Could not read amiibo data from file \"{}\"", amiibo_filename_);
        encrypted_tag.file = {};
        return false;
    }

    // TODO: Filter by allowed_protocols here

    amiibo_filename = amiibo_filename_;
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

    amiibo_filename = "";
    device_state = DeviceState::TagRemoved;
    encrypted_tag.file = {};
    tag.file = {};
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
    encrypted_tag.file = {};
    tag.file = {};
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
        return ResultWrongDeviceState;
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
    }

    if (device_state == DeviceState::SearchingForTag || device_state == DeviceState::TagRemoved) {
        device_state = DeviceState::Initialized;
        return RESULT_SUCCESS;
    }

    LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
    return ResultWrongDeviceState;
}

ResultCode NfcDevice::Flush() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    auto& settings = tag.file.settings;

    const auto& current_date = GetAmiiboDate();
    if (settings.write_date.raw_date != current_date.raw_date) {
        settings.write_date = current_date;
        UpdateSettingsCrc();
    }

    tag.file.write_counter++;

    if (!AmiiboCrypto::EncodeAmiibo(tag.file, encrypted_tag.file)) {
        LOG_ERROR(Service_NFC, "Failed to encode data");
        return ResultWriteAmiiboFailed;
    }

    std::vector<u8> data(sizeof(encrypted_tag.file));
    memcpy(data.data(), &encrypted_tag.file, sizeof(encrypted_tag.file));

    if (amiibo_filename.empty()) {
        LOG_ERROR(Service_NFC, "Tried to use UpdateStoredAmiiboData on a nonexistant file.");
        return ResultWriteAmiiboFailed;
    }

    FileUtil::IOFile amiibo_file(amiibo_filename, "wb");
    bool write_failed = false;

    if (!amiibo_file.IsOpen()) {
        LOG_ERROR(Service_NFC, "Could not open amiibo file \"{}\"", amiibo_filename);
        write_failed = true;
    }
    if (!write_failed && !amiibo_file.WriteBytes(data.data(), sizeof(data))) {
        LOG_ERROR(Service_NFC, "Could not write to amiibo file \"{}\"", amiibo_filename);
        write_failed = true;
    }
    amiibo_file.Close();

    if (write_failed) {
        return ResultWriteAmiiboFailed;
    }

    is_data_moddified = false;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::Mount(MountTarget mount_target_) {
    if (device_state != DeviceState::TagFound) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        return ResultWrongDeviceState;
    }

    if (!AmiiboCrypto::IsAmiiboValid(encrypted_tag.file)) {
        LOG_ERROR(Service_NFC, "Not an amiibo");
        return ResultNotAnAmiibo;
    }

    // Mark amiibos as read only when keys are missing
    if (!AmiiboCrypto::IsKeyAvailable()) {
        LOG_ERROR(Service_NFC, "No keys detected");
        device_state = DeviceState::TagMounted;
        mount_target = MountTarget::Rom;
        return RESULT_SUCCESS;
    }

    if (!AmiiboCrypto::DecodeAmiibo(encrypted_tag.file, tag.file)) {
        LOG_ERROR(Service_NFC, "Can't decode amiibo {}", device_state);
        return ResultCorruptedData;
    }

    device_state = DeviceState::TagMounted;
    mount_target = mount_target_;
    return RESULT_SUCCESS;
}

ResultCode NfcDevice::Unmount() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
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
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    tag_info = {
        .uuid_length = static_cast<u16>(encrypted_tag.file.uuid.uid.size()),
        .tag_type = PackedTagType::Type2,
        .uuid = encrypted_tag.file.uuid.uid,
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
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    tag_info = {
        .uuid_length = static_cast<u16>(encrypted_tag.file.uuid.uid.size()),
        .protocol = PackedTagProtocol::None,
        .tag_type = PackedTagType::Type2,
        .uuid = encrypted_tag.file.uuid.uid,
        .extra_data = {}, // Used on non amiibo tags
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetCommonInfo(CommonInfo& common_info) const {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    const auto& settings = tag.file.settings;
    const auto& model_info_data = tag.file.model_info;

    // TODO: Validate this data
    common_info = {
        .last_write_date = settings.write_date.GetWriteDate(),
        .write_counter = tag.file.write_counter,
        .character_id = model_info_data.character_id,
        .character_variant = model_info_data.character_variant,
        .series = model_info_data.series,
        .model_number = model_info_data.model_number,
        .amiibo_type = model_info_data.amiibo_type,
        .version = tag.file.amiibo_version,
        .application_area_size = sizeof(ApplicationArea),
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetModelInfo(ModelInfo& model_info) const {
    if (device_state != DeviceState::TagFound && device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    const auto& model_info_data = encrypted_tag.file.user_memory.model_info;
    model_info = {
        .character_id = model_info_data.character_id,
        .character_variant = model_info_data.character_variant,
        .series = model_info_data.series,
        .model_number = model_info_data.model_number,
        .amiibo_type = model_info_data.amiibo_type,
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetRegisterInfo(RegisterInfo& register_info) const {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.amiibo_initialized == 0) {
        return ResultRegistrationIsNotInitialized;
    }

    const auto& settings = tag.file.settings;

    // TODO: Validate this data
    register_info = {
        .mii_data = tag.file.owner_mii,
        .amiibo_name = GetAmiiboName(settings),
        .flags = settings.settings,
        .font_region = settings.settings.font_region,
        .creation_date = settings.init_date.GetWriteDate(),
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetAdminInfo(AdminInfo& admin_info) const {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    u8 flags = static_cast<u8>(tag.file.settings.settings.raw >> 0x4);
    if (tag.file.settings.settings.amiibo_initialized == 0) {
        flags = flags & 0xfe;
    }

    u64 application_id = 0;
    u32 application_area_id = 0;
    AppAreaVersion app_area_version = AppAreaVersion::NotSet;
    if (tag.file.settings.settings.appdata_initialized != 0) {
        application_id = tag.file.application_id;
        app_area_version =
            static_cast<AppAreaVersion>(application_id >> application_id_version_offset & 0xf);

        // Restore application id to original value
        if (application_id >> 0x38 != 0) {
            const u8 application_byte = tag.file.application_id_byte & 0xf;
            application_id &= ~(0xfULL << application_id_version_offset);
            application_id |= static_cast<u64>(application_byte) << application_id_version_offset;
        }

        application_area_id = tag.file.application_area_id;
    }

    // TODO: Validate this data
    admin_info = {
        .application_id = application_id,
        .application_area_id = application_area_id,
        .crc_change_counter = tag.file.settings.crc_counter,
        .flags = flags,
        .tag_type = PackedTagType::Type2,
        .app_area_version = app_area_version,
    };

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::DeleteRegisterInfo() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.amiibo_initialized == 0) {
        return ResultRegistrationIsNotInitialized;
    }

    CryptoPP::AutoSeededRandomPool rng;
    const std::size_t data_size = sizeof(tag.file.owner_mii);
    std::array<CryptoPP::byte, data_size> buffer{};
    rng.GenerateBlock(buffer.data(), data_size);

    memcpy(&tag.file.owner_mii, buffer.data(), data_size);
    memcpy(&tag.file.settings.amiibo_name, buffer.data(), sizeof(tag.file.settings.amiibo_name));
    tag.file.unknown = rng.GenerateByte();
    tag.file.unknown2[0] = rng.GenerateWord32();
    tag.file.unknown2[1] = rng.GenerateWord32();
    tag.file.application_area_crc = rng.GenerateWord32();
    tag.file.settings.init_date.raw_date = static_cast<u32>(rng.GenerateWord32());
    tag.file.settings.settings.font_region.Assign(0);
    tag.file.settings.settings.amiibo_initialized.Assign(0);

    return Flush();
}

ResultCode NfcDevice::SetRegisterInfoPrivate(const AmiiboName& amiibo_name) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    auto& settings = tag.file.settings;

    if (tag.file.settings.settings.amiibo_initialized == 0) {
        settings.init_date = GetAmiiboDate();
        settings.write_date = GetAmiiboDate();
    }

    // TODO: Calculate mii checksum
    // tag.file.owner_mii_aes_ccm = ? ? ? ? ;

    SetAmiiboName(settings, amiibo_name);
    tag.file.owner_mii = HLE::Applets::MiiSelector::GetStandardMiiResult().selected_mii_data;
    tag.file.unknown = 0;
    tag.file.unknown2[6] = 0;
    settings.country_code_id = 0;
    settings.settings.font_region.Assign(0);
    settings.settings.amiibo_initialized.Assign(1);

    // TODO: this is a mix of tag.file input
    std::array<u8, 0x7e> unknown_input{};
    tag.file.application_area_crc = CalculateCrc(unknown_input);

    return Flush();
}

ResultCode NfcDevice::RestoreAmiibo() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    // TODO: Load amiibo from backup on system
    LOG_ERROR(Service_NFC, "Not Implemented");
    return RESULT_SUCCESS;
}

ResultCode NfcDevice::Format() {
    auto ResultCode = DeleteApplicationArea();
    auto ResultCode2 = DeleteRegisterInfo();

    if (ResultCode.IsError()) {
        return ResultCode;
    }

    if (ResultCode2.IsError()) {
        return ResultCode2;
    }

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::OpenApplicationArea(u32 access_id) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.appdata_initialized.Value() == 0) {
        LOG_WARNING(Service_NFC, "Application area is not initialized");
        return ResultApplicationAreaIsNotInitialized;
    }

    if (tag.file.application_area_id != access_id) {
        LOG_WARNING(Service_NFC, "Wrong application area id");
        return ResultWrongApplicationAreaId;
    }

    is_app_area_open = true;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetApplicationAreaId(u32& application_area_id) const {
    application_area_id = {};

    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.appdata_initialized.Value() == 0) {
        LOG_WARNING(Service_NFC, "Application area is not initialized");
        return ResultApplicationAreaIsNotInitialized;
    }

    application_area_id = tag.file.application_area_id;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::GetApplicationArea(std::vector<u8>& data) const {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (!is_app_area_open) {
        LOG_ERROR(Service_NFC, "Application area is not open");
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.appdata_initialized.Value() == 0) {
        LOG_ERROR(Service_NFC, "Application area is not initialized");
        return ResultApplicationAreaIsNotInitialized;
    }

    if (data.size() > sizeof(ApplicationArea)) {
        data.resize(sizeof(ApplicationArea));
    }

    memcpy(data.data(), tag.file.application_area.data(), data.size());

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::SetApplicationArea(std::span<const u8> data) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (!is_app_area_open) {
        LOG_ERROR(Service_NFC, "Application area is not open");
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.appdata_initialized.Value() == 0) {
        LOG_ERROR(Service_NFC, "Application area is not initialized");
        return ResultApplicationAreaIsNotInitialized;
    }

    if (data.size() > sizeof(ApplicationArea)) {
        LOG_ERROR(Service_NFC, "Wrong data size {}", data.size());
        return ResultWrongDeviceState;
    }

    std::memcpy(tag.file.application_area.data(), data.data(), data.size());

    // Fill remaining data with random numbers
    CryptoPP::AutoSeededRandomPool rng;
    const std::size_t data_size = sizeof(ApplicationArea) - data.size();
    std::vector<CryptoPP::byte> buffer(data_size);
    rng.GenerateBlock(buffer.data(), data_size);
    memcpy(tag.file.application_area.data() + data.size(), buffer.data(), data_size);

    if (tag.file.application_write_counter != counter_limit) {
        tag.file.application_write_counter++;
    }

    is_data_moddified = true;

    return RESULT_SUCCESS;
}

ResultCode NfcDevice::CreateApplicationArea(u32 access_id, std::span<const u8> data) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.appdata_initialized.Value() != 0) {
        LOG_ERROR(Service_NFC, "Application area already exist");
        return ResultApplicationAreaExist;
    }

    return RecreateApplicationArea(access_id, data);
}

ResultCode NfcDevice::RecreateApplicationArea(u32 access_id, std::span<const u8> data) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (data.size() > sizeof(ApplicationArea)) {
        LOG_ERROR(Service_NFC, "Wrong data size {}", data.size());
        return ResultWrongApplicationAreaSize;
    }

    std::memcpy(tag.file.application_area.data(), data.data(), data.size());

    // Fill remaining data with random numbers
    CryptoPP::AutoSeededRandomPool rng;
    const std::size_t data_size = sizeof(ApplicationArea) - data.size();
    std::vector<CryptoPP::byte> buffer(data_size);
    rng.GenerateBlock(buffer.data(), data_size);
    memcpy(tag.file.application_area.data() + data.size(), buffer.data(), data_size);

    if (tag.file.application_write_counter != counter_limit) {
        tag.file.application_write_counter++;
    }

    u64 application_id{};
    if (Core::System::GetInstance().GetAppLoader().ReadProgramId(application_id) ==
        Loader::ResultStatus::Success) {
        const u64 application_id_without_version_byte =
            application_id & ~(0xfULL << application_id_version_offset);

        tag.file.application_id_byte =
            static_cast<u8>(application_id >> application_id_version_offset & 0xf);
        tag.file.application_id =
            application_id_without_version_byte |
            (static_cast<u64>(AppAreaVersion::Nintendo3DSv2) << application_id_version_offset);
    }
    tag.file.settings.settings.appdata_initialized.Assign(1);
    tag.file.application_area_id = access_id;
    tag.file.unknown = {};

    // TODO: this is a mix of tag.file input
    std::array<u8, 0x7e> unknown_input{};
    tag.file.application_area_crc = CalculateCrc(unknown_input);

    return Flush();
}

ResultCode NfcDevice::DeleteApplicationArea() {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    if (tag.file.settings.settings.appdata_initialized == 0) {
        return ResultApplicationAreaIsNotInitialized;
    }

    CryptoPP::AutoSeededRandomPool rng;
    constexpr std::size_t data_size = sizeof(ApplicationArea);
    std::array<CryptoPP::byte, data_size> buffer{};
    rng.GenerateBlock(buffer.data(), data_size);

    if (tag.file.application_write_counter != counter_limit) {
        tag.file.application_write_counter++;
    }

    // Reset data with random bytes
    memcpy(tag.file.application_area.data(), buffer.data(), data_size);
    memcpy(&tag.file.application_id, buffer.data(), sizeof(u64));
    tag.file.application_area_id = rng.GenerateWord32();
    tag.file.application_id_byte = rng.GenerateByte();
    tag.file.settings.settings.appdata_initialized.Assign(0);
    tag.file.unknown = {};

    return Flush();
}

ResultCode NfcDevice::ApplicationAreaExist(bool& has_application_area) {
    if (device_state != DeviceState::TagMounted) {
        LOG_ERROR(Service_NFC, "Wrong device state {}", device_state);
        if (device_state == DeviceState::TagRemoved) {
            return ResultTagRemoved;
        }
        return ResultWrongDeviceState;
    }

    if (mount_target == MountTarget::None || mount_target == MountTarget::Rom) {
        LOG_ERROR(Service_NFC, "Amiibo is read only", device_state);
        return ResultWrongDeviceState;
    }

    has_application_area = tag.file.settings.settings.appdata_initialized.Value() != 0;

    return RESULT_SUCCESS;
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

void NfcDevice::UpdateSettingsCrc() {
    auto& settings = tag.file.settings;

    if (settings.crc_counter != counter_limit) {
        settings.crc_counter++;
    }

    // TODO: this reads data from a global, find what it is
    std::array<u8, 8> unknown_input{};
    settings.crc = CalculateCrc(unknown_input);
}

u32 NfcDevice::CalculateCrc(std::span<u8> data) {
    constexpr u32 magic = 0xedb88320;
    u32 crc = 0xffffffff;

    if (data.size() == 0) {
        return 0;
    }

    for (u8 input : data) {
        u32 temp = (crc ^ input) >> 1;
        if (((crc ^ input) & 1) != 0) {
            temp = temp ^ magic;
        }

        for (std::size_t step = 0; step < 7; ++step) {
            crc = temp >> 1;
            if ((temp & 1) != 0) {
                crc = temp >> 1 ^ magic;
            }
        }
    }

    return ~crc;
}

} // namespace Service::NFC
