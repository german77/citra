// SPDX-FileCopyrightText: Copyright 2022 yuzu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "core/hle/result.h"

namespace Service::NFC {

namespace ErrCodes {
enum {
    CommandInvalidForState = 512,
};
} // namespace ErrCodes

constexpr ResultCode DeviceNotFound(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                    ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode InvalidArgument(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                     ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode WrongApplicationAreaSize(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                              ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode WrongDeviceState(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                      ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode NfcDisabled(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                 ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode WriteAmiiboFailed(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                       ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode TagRemoved(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode RegistrationIsNotInitialized(ErrCodes::CommandInvalidForState,
                                                  ErrorModule::NFC, ErrorSummary::InvalidState,
                                                  ErrorLevel::Status);
constexpr ResultCode ApplicationAreaIsNotInitialized(ErrCodes::CommandInvalidForState,
                                                     ErrorModule::NFC, ErrorSummary::InvalidState,
                                                     ErrorLevel::Status);
constexpr ResultCode CorruptedData(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                   ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode WrongApplicationAreaId(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                            ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ApplicationAreaExist(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                          ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode NotAnAmiibo(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                 ErrorSummary::InvalidState, ErrorLevel::Status);

} // namespace Service::NFC
