// Copyright 2016 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "common/archives.h"
#include "core/core.h"
#include "core/hle/ipc_helpers.h"
#include "core/hle/kernel/event.h"
#include "core/hle/lock.h"
#include "core/hle/service/nfc/nfc.h"
#include "core/hle/service/nfc/nfc_m.h"
#include "core/hle/service/nfc/nfc_u.h"

SERVICE_CONSTRUCT_IMPL(Service::NFC::Module)
SERIALIZE_EXPORT_IMPL(Service::NFC::Module)

namespace Service::NFC {

template <class Archive>
void Module::serialize(Archive& ar, const unsigned int) {
    ar& nfc_status;
    ar& device;
}
SERIALIZE_IMPL(Module)

void Module::Interface::Initialize(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x01, 1, 0);
    u8 param = rp.Pop<u8>();

    nfc->device->Initialize();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
    LOG_INFO(Service_NFC, "called, param={}", param);
}

void Module::Interface::Shutdown(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x02, 1, 0);
    u8 param = rp.Pop<u8>();

    nfc->device->Finalize();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
    LOG_INFO(Service_NFC, "called, param={}", param);
}

void Module::Interface::StartCommunication(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x03, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
    LOG_WARNING(Service_NFC, "(STUBBED) called");
}

void Module::Interface::StopCommunication(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x04, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
    LOG_WARNING(Service_NFC, "(STUBBED) called");
}

void Module::Interface::StartTagScanning(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x05, 1, 0);
    u16 in_val = rp.Pop<u16>();

    // in_val probably correlates to the tag protocol to be detected
    const auto result = nfc->device->StartDetection(TagProtocol::All);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called, in_val={:04x}", in_val);
}

void Module::Interface::StopTagScanning(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x06, 0, 0);

    const auto result = nfc->device->StopDetection();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::LoadAmiiboData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x07, 0, 0);

    const auto result = nfc->device->Mount(MountTarget::All);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::ResetTagScanState(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x08, 0, 0);

    const auto result = nfc->device->Unmount();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::UpdateStoredAmiiboData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x09, 0, 0);

    const auto result = nfc->device->Flush();

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::GetTagInRangeEvent(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0B, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(RESULT_SUCCESS);
    rb.PushCopyObjects(nfc->device->GetActivateEvent());
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::GetTagOutOfRangeEvent(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0C, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(RESULT_SUCCESS);
    rb.PushCopyObjects(nfc->device->GetDeactivateEvent());
    LOG_DEBUG(Service_NFC, "called");
}

void Module::Interface::GetTagState(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0D, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.PushEnum(nfc->device->GetCurrentState());
    LOG_DEBUG(Service_NFC, "called");
}

void Module::Interface::CommunicationGetStatus(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x0F, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.PushEnum(nfc->nfc_status);
    LOG_DEBUG(Service_NFC, "(STUBBED) called");
}

void Module::Interface::GetTagInfo2(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x10, 0, 0);

    TagInfo2 tag_info{};
    const auto result = nfc->device->GetTagInfo2(tag_info);

    IPC::RequestBuilder rb = rp.MakeBuilder(26, 0);
    rb.Push(result);
    rb.PushRaw<TagInfo2>(tag_info);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::GetTagInfo(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x11, 0, 0);

    TagInfo tag_info{};
    const auto result = nfc->device->GetTagInfo(tag_info);

    IPC::RequestBuilder rb = rp.MakeBuilder(12, 0);
    rb.Push(result);
    rb.PushRaw<TagInfo>(tag_info);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::CommunicationGetResult(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x12, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(2, 0);
    rb.Push(RESULT_SUCCESS);
    rb.Push(0);
    LOG_WARNING(Service_NFC, "(STUBBED) called");
}

void Module::Interface::OpenAppData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x13, 1, 0);
    u32 access_id = rp.Pop<u32>();

    const auto result = nfc->device->OpenApplicationArea(access_id);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::InitializeWriteAppData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x14, 18, 2);
    u32 access_id = rp.Pop<u32>();
    u32 size = rp.Pop<u32>();
    std::vector<u8> buffer = rp.PopStaticBuffer();

    const auto result = nfc->device->CreateApplicationArea(access_id, buffer);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::ReadAppData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x15, 0, 0);

    std::vector<u8> buffer(sizeof(ApplicationArea));
    const auto result = nfc->device->GetApplicationArea(buffer);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 2);
    rb.Push(result);
    rb.PushStaticBuffer(buffer, 0);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::WriteAppData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x16, 12, 2);
    u32 size = rp.Pop<u32>();
    std::vector<u8> tag_uuid_info = rp.PopStaticBuffer();
    std::vector<u8> buffer = rp.PopStaticBuffer();

    const auto result = nfc->device->SetApplicationArea(buffer);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(result);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::GetAmiiboSettings(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x17, 0, 0);

    SettingsInfo settings_info{};
    const auto result = nfc->device->GetSettingInfo(settings_info);

    IPC::RequestBuilder rb = rp.MakeBuilder(43, 0);
    rb.Push(result);
    rb.PushRaw<SettingsInfo>(settings_info);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::GetAmiiboConfig(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x18, 0, 0);

    AmiiboConfig amiibo_config{};
    const auto result = nfc->device->GetAmiiboConfig(amiibo_config);

    IPC::RequestBuilder rb = rp.MakeBuilder(17, 0);
    rb.Push(result);
    rb.PushRaw<AmiiboConfig>(amiibo_config);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::GetAppDataInitStruct(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x19, 0, 0);

    using InitialStruct = std::array<u8, 0x3c>;
    InitialStruct empty{};

    IPC::RequestBuilder rb = rp.MakeBuilder(16, 0);
    rb.Push(RESULT_SUCCESS);
    rb.PushRaw<InitialStruct>(empty);
    LOG_WARNING(Service_NFC, "(STUBBED) called");
}

void Module::Interface::Unknown0x1A(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x1A, 0, 0);

    IPC::RequestBuilder rb = rp.MakeBuilder(1, 0);
    rb.Push(RESULT_SUCCESS);
    LOG_DEBUG(Service_NFC, "(STUBBED) called");
}

void Module::Interface::GetIdentificationBlock(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x1B, 0, 0);

    ModelInfo model_info{};
    const auto result = nfc->device->GetModelInfo(model_info);

    IPC::RequestBuilder rb = rp.MakeBuilder(0x1F, 0);
    rb.Push(result);
    rb.PushRaw<ModelInfo>(model_info);
    LOG_INFO(Service_NFC, "called");
}

void Module::Interface::ResetAmiiboSettings(Kernel::HLERequestContext& ctx) {
    // Please fix this part it's probably wrong
    IPC::RequestParser rp(ctx, 0x401, 0, 0);

    const auto result = nfc->device->DeleteAllData();

    IPC::RequestBuilder rb = rp.MakeBuilder(0x1, 0);
    rb.Push(result);
    LOG_WARNING(Service_NFC, "(STUBBED) called");
}

void Module::Interface::SetAmiiboSettings(Kernel::HLERequestContext& ctx) {
    // Please fix this part it's probably wrong
    IPC::RequestParser rp(ctx, 0x404, 41, 0);

    // TODO: Pull amiibo settings from request parser
    AmiiboName name{0x43, 0x69, 0x74, 0x72, 0x61, 0x00}; // Citra

    const auto result = nfc->device->SetNicknameAndOwner(name);

    IPC::RequestBuilder rb = rp.MakeBuilder(0x1, 0);
    rb.Push(result);
    LOG_WARNING(Service_NFC, "(STUBBED) called");
}

void Module::Interface::DeleteAppData(Kernel::HLERequestContext& ctx) {
    IPC::RequestParser rp(ctx, 0x406, 0, 0);

    const auto result = nfc->device->DeleteApplicationArea();

    IPC::RequestBuilder rb = rp.MakeBuilder(0x1, 0);
    rb.Push(result);
    LOG_WARNING(Service_NFC, "(STUBBED) called");
}

std::shared_ptr<Module> Module::Interface::GetModule() const {
    return nfc;
}

bool Module::Interface::LoadAmiibo(const std::string& fullpath) {
    std::lock_guard lock(HLE::g_hle_lock);
    return nfc->device->LoadAmiibo(fullpath);
}

void Module::Interface::RemoveAmiibo() {
    std::lock_guard lock(HLE::g_hle_lock);
    nfc->device->CloseAmiibo();
}

Module::Interface::Interface(std::shared_ptr<Module> nfc, const char* name, u32 max_session)
    : ServiceFramework(name, max_session), nfc(std::move(nfc)) {}

Module::Interface::~Interface() = default;

Module::Module(Core::System& system) {
    device = std::make_shared<NfcDevice>(system);
}

Module::~Module() = default;

void InstallInterfaces(Core::System& system) {
    auto& service_manager = system.ServiceManager();
    auto nfc = std::make_shared<Module>(system);
    std::make_shared<NFC_M>(nfc)->InstallAsService(service_manager);
    std::make_shared<NFC_U>(nfc)->InstallAsService(service_manager);
}

} // namespace Service::NFC
