/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2018-2023 Simon Rozman <simon@rozman.si>
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

#include <Windows.h>
#include <Msi.h>

#include <stdbool.h>

/*
 * Error codes (next unused 2552L)
 */
#define ERROR_MSICA       2550L
#define ERROR_MSICA_ERRNO 2551L

#define M_FATAL           (1<<4)         /* exit program */
#define M_NONFATAL        (1<<5)         /* non-fatal error */
#define M_WARN            (1<<6)         /* call syslog with LOG_WARNING */
#define M_ERRNO           (1<<8)         /* show errno description */


 /**
  * MSI session handle thread local storage index
  */
extern DWORD ovpndco_thread_data_idx;

/**
 * Thread local storage data
 */
struct ovpndco_thread_data
{
    MSIHANDLE hInstall; /** Handle to the installation session. */
};

/**
 * Set MSI session handle in thread local storage.
 */
#define OVPNDCO_SAVE_MSI_SESSION(handle) \
    { \
        struct ovpndco_thread_data *s = (struct ovpndco_thread_data *)TlsGetValue(ovpndco_thread_data_idx); \
        s->hInstall = (handle); \
    }

#define EXIT_FATAL(flags) do { if ((flags) & M_FATAL) {_exit(1);}} while (false)

void x_msg(const unsigned int flags, const char* format, ...);

void x_msg_va(const unsigned int flags, const char* format, va_list arglist);

#define msg(flags, ...) do { x_msg((flags), __VA_ARGS__); EXIT_FATAL(flags); } while (false)
