/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
 *
 *  Author:	Lev Stipakov <lev@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntintsafe.h>

#include <evntrace.h>
#include <TraceLoggingProvider.h>

TRACELOGGING_DECLARE_PROVIDER(OpenVPNTraceProvider);

#define TraceLoggingFunctionName() TraceLoggingWideString(__FUNCTIONW__, "Func")

#define LOG_NTSTATUS(Status, ...) do {\
        TraceLoggingWrite( \
            OpenVPNTraceProvider, \
            "Status", \
            TraceLoggingLevel(TRACE_LEVEL_ERROR), \
            TraceLoggingFunctionName(), \
            TraceLoggingUInt32(__LINE__, "Line"), \
            TraceLoggingNTStatus(Status, "Status"), \
            __VA_ARGS__); \
} while (0,0)

#define LOG_ERROR(Error, ...) do {\
        TraceLoggingWrite( \
            OpenVPNTraceProvider, \
            "Error", \
            TraceLoggingLevel(TRACE_LEVEL_ERROR), \
            TraceLoggingFunctionName(), \
            TraceLoggingUInt32(__LINE__, "Line"), \
            TraceLoggingValue(Error, "Msg"), \
            __VA_ARGS__); \
} while (0,0)

#define LOG_WARN(Info, ...) do {\
        TraceLoggingWrite( \
            OpenVPNTraceProvider, \
            "Warn", \
            TraceLoggingLevel(TRACE_LEVEL_WARNING), \
            TraceLoggingFunctionName(), \
            TraceLoggingUInt32(__LINE__, "Line"), \
            TraceLoggingValue(Info, "Msg"), \
            __VA_ARGS__); \
} while (0,0)

#define LOG_INFO(Info, ...) do {\
        TraceLoggingWrite( \
            OpenVPNTraceProvider, \
            "Info", \
            TraceLoggingLevel(TRACE_LEVEL_INFORMATION), \
            TraceLoggingFunctionName(), \
            TraceLoggingUInt32(__LINE__, "Line"), \
            TraceLoggingValue(Info, "Msg"), \
            __VA_ARGS__); \
} while (0,0)

#define LOG_IF_NOT_NT_SUCCESS(Expression, ...) do {\
    NTSTATUS p_status = (Expression); \
    if (!NT_SUCCESS(p_status)) \
    { \
        LOG_NTSTATUS(p_status, \
            TraceLoggingWideString(L#Expression, "Expression"), \
            __VA_ARGS__); \
    } \
} while(0,0)

#define GOTO_IF_NOT_NT_SUCCESS(Label, StatusLValue, Expression, ...) do {\
    StatusLValue = (Expression); \
    if (!NT_SUCCESS(StatusLValue)) \
    { \
        LOG_NTSTATUS(StatusLValue, \
            TraceLoggingWideString(L#Expression, "Expression"), \
            __VA_ARGS__); \
        goto Label; \
    } \
} while(0,0)
