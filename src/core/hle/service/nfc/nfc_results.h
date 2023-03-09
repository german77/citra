// Copyright 2023 Citra Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include "core/hle/result.h"

namespace Service::NFC {

namespace ErrCodes {
enum {
    CommandInvalidForState = 512,
    AppDataUninitialized = 544,
    AmiiboNotSetup = 552,
    AppIdMismatch = 568,
    NotAnAmiibo = 524,
    CorruptedData = 536
};
} // namespace ErrCodes

constexpr ResultCode ResultDeviceNotFound(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                          ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultInvalidArgument(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                           ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultWrongApplicationAreaSize(ErrCodes::CommandInvalidForState,
                                                    ErrorModule::NFC, ErrorSummary::InvalidState,
                                                    ErrorLevel::Status);
constexpr ResultCode ResultWrongDeviceState(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                            ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultNfcDisabled(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                       ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultWriteAmiiboFailed(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                             ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultTagRemoved(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                      ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultRegistrationIsNotInitialized(ErrCodes::AmiiboNotSetup, ErrorModule::NFC,
                                                        ErrorSummary::InvalidState,
                                                        ErrorLevel::Status);
constexpr ResultCode ResultApplicationAreaIsNotInitialized(ErrCodes::AppDataUninitialized,
                                                           ErrorModule::NFC,
                                                           ErrorSummary::InvalidState,
                                                           ErrorLevel::Status);
constexpr ResultCode ResultCorruptedData(ErrCodes::CorruptedData, ErrorModule::NFC,
                                         ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultWrongApplicationAreaId(ErrCodes::AppIdMismatch, ErrorModule::NFC,
                                                  ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultApplicationAreaExist(ErrCodes::CommandInvalidForState, ErrorModule::NFC,
                                                ErrorSummary::InvalidState, ErrorLevel::Status);
constexpr ResultCode ResultNotAnAmiibo(ErrCodes::NotAnAmiibo, ErrorModule::NFC,
                                       ErrorSummary::InvalidState, ErrorLevel::Status);

} // namespace Service::NFC
