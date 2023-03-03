// Copyright 2016 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <memory>
#include "common/common_funcs.h"
#include "common/common_types.h"
#include "core/hle/applets/applet.h"
#include "core/hle/kernel/shared_memory.h"
#include "core/hle/result.h"
#include "core/hle/service/apt/apt.h"

namespace Frontend {
class MiiSelector;
struct MiiSelectorConfig;
} // namespace Frontend

namespace HLE::Applets {

struct MiiConfig {
    u8 enable_cancel_button;
    u8 enable_guest_mii;
    u8 show_on_top_screen;
    INSERT_PADDING_BYTES(5);
    std::array<u16_le, 0x40> title;
    INSERT_PADDING_BYTES(4);
    u8 show_guest_miis;
    INSERT_PADDING_BYTES(3);
    u32 initially_selected_mii_index;
    std::array<u8, 0x6> guest_mii_whitelist;
    std::array<u8, 0x64> user_mii_whitelist;
    INSERT_PADDING_BYTES(2);
    u32 magic_value;
};
static_assert(sizeof(MiiConfig) == 0x104, "MiiConfig structure has incorrect size");
#define ASSERT_REG_POSITION(field_name, position)                                                  \
    static_assert(offsetof(MiiConfig, field_name) == position,                                     \
                  "Field " #field_name " has invalid position")
ASSERT_REG_POSITION(title, 0x08);
ASSERT_REG_POSITION(show_guest_miis, 0x8C);
ASSERT_REG_POSITION(initially_selected_mii_index, 0x90);
ASSERT_REG_POSITION(guest_mii_whitelist, 0x94);
#undef ASSERT_REG_POSITION

#pragma pack(push, 1)
struct MiiData {
    u32_be mii_id;
    u64_be system_id;
    u32_be specialness_and_creation_date;
    std::array<u8, 0x6> creator_mac;
    u16_be padding;
    union {
        u16 raw;

        BitField<0, 1, u16> gender;
        BitField<1, 4, u16> birth_month;
        BitField<5, 5, u16> birth_day;
        BitField<10, 4, u16> favorite_color;
        BitField<14, 1, u16> favorite;
    } mii_information;
    std::array<u16_le, 0xA> mii_name;
    u8 height;
    u8 build;
    union {
        u8 raw;

        BitField<0, 1, u8> disable_sharing;
        BitField<1, 4, u8> face_shape;
        BitField<5, 3, u8> skin_color;
    } appearance_bits1;
    union {
        u8 raw;

        BitField<0, 4, u8> wrinkles;
        BitField<4, 4, u8> makeup;
    } appearance_bits2;
    u8 hair_style;
    union {
        u8 raw;

        BitField<0, 3, u8> hair_color;
        BitField<3, 1, u8> flip_hair;
    } appearance_bits3;
    union {
        u32 raw;

        BitField<0, 6, u32> eye_type;
        BitField<6, 3, u32> eye_color;
        BitField<9, 4, u32> eye_scale;
        BitField<13, 3, u32> eye_vertical_stretch;
        BitField<16, 5, u32> eye_rotation;
        BitField<21, 4, u32> eye_spacing;
        BitField<25, 5, u32> eye_y_position;
    } appearance_bits4;
    union {
        u32 raw;

        BitField<0, 5, u32> eyebrow_style;
        BitField<5, 3, u32> eyebrow_color;
        BitField<8, 4, u32> eyebrow_scale;
        BitField<12, 3, u32> eyebrow_yscale;
        BitField<16, 4, u32> eyebrow_rotation;
        BitField<21, 4, u32> eyebrow_spacing;
        BitField<25, 5, u32> eyebrow_y_position;
    } appearance_bits5;
    union {
        u16 raw;

        BitField<0, 5, u16> nose_type;
        BitField<5, 4, u16> nose_scale;
        BitField<9, 5, u16> nose_y_position;
    } appearance_bits6;
    union {
        u16 raw;

        BitField<0, 6, u16> mouth_type;
        BitField<6, 3, u16> mouth_color;
        BitField<9, 4, u16> mouth_scale;
        BitField<13, 3, u16> mouth_horizontal_stretch;
    } appearance_bits7;
    union {
        u8 raw;

        BitField<0, 5, u8> mouth_y_position;
        BitField<5, 3, u8> mustache_type;
    } appearance_bits8;
    u8 allow_copying;
    union {
        u16 raw;

        BitField<0, 3, u16> bear_type;
        BitField<3, 3, u16> facial_hair_color;
        BitField<6, 4, u16> mustache_scale;
        BitField<10, 5, u16> mustache_y_position;
    } appearance_bits9;
    union {
        u16 raw;

        BitField<0, 4, u16> glasses_type;
        BitField<4, 3, u16> glasses_color;
        BitField<7, 4, u16> glasses_scale;
        BitField<11, 5, u16> glasses_y_position;
    } appearance_bits10;
    union {
        u16 raw;

        BitField<0, 1, u16> mole_enabled;
        BitField<1, 4, u16> mole_scale;
        BitField<5, 5, u16> mole_x_position;
        BitField<10, 5, u16> mole_y_position;
    } appearance_bits11;
    std::array<u16_le, 0xA> author_name;
};
static_assert(sizeof(MiiData) == 0x5C, "MiiData structure has incorrect size");
#pragma pack(pop)

struct MiiResult {
    u32_be return_code;
    u32_be is_guest_mii_selected;
    u32_be selected_guest_mii_index;
    MiiData selected_mii_data;
    u16_be unknown1;
    u16_be mii_data_checksum;
    std::array<u16_le, 0xC> guest_mii_name;
};
static_assert(sizeof(MiiResult) == 0x84, "MiiResult structure has incorrect size");
#define ASSERT_REG_POSITION(field_name, position)                                                  \
    static_assert(offsetof(MiiResult, field_name) == position,                                     \
                  "Field " #field_name " has invalid position")
ASSERT_REG_POSITION(selected_mii_data, 0x0C);
ASSERT_REG_POSITION(guest_mii_name, 0x6C);
#undef ASSERT_REG_POSITION

class MiiSelector final : public Applet {
public:
    MiiSelector(Service::APT::AppletId id, Service::APT::AppletId parent, bool preload,
                std::weak_ptr<Service::APT::AppletManager> manager)
        : Applet(id, parent, preload, std::move(manager)) {}

    ResultCode ReceiveParameterImpl(const Service::APT::MessageParameter& parameter) override;
    ResultCode Start(const Service::APT::MessageParameter& parameter) override;
    ResultCode Finalize() override;
    void Update() override;

    static MiiResult GetStandardMiiResult();

private:
    Frontend::MiiSelectorConfig ToFrontendConfig(const MiiConfig& config) const;

    /// This SharedMemory will be created when we receive the LibAppJustStarted message.
    /// It holds the framebuffer info retrieved by the application with
    /// GSPGPU::ImportDisplayCaptureInfo
    std::shared_ptr<Kernel::SharedMemory> framebuffer_memory;

    MiiConfig config;

    MiiResult result{};

    std::shared_ptr<Frontend::MiiSelector> frontend_applet;
};
} // namespace HLE::Applets
