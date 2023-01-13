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

#include <windows.h>

#include "log.h"

DWORD ovpndco_thread_data_idx = TLS_OUT_OF_INDEXES;

/**
 * DLL entry point
 */
BOOL WINAPI
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD dwReason,
    _In_ LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        /* Allocate thread local storage index. */
        ovpndco_thread_data_idx = TlsAlloc();
        if (ovpndco_thread_data_idx == TLS_OUT_OF_INDEXES)
        {
            return FALSE;
        }
        /* Fall through. */

    case DLL_THREAD_ATTACH:
    {
        /* Create thread local storage data. */
        struct ovpndco_thread_data* s = (struct ovpndco_thread_data*)calloc(1, sizeof(struct ovpndco_thread_data));
        if (s == NULL)
        {
            return FALSE;
        }

        TlsSetValue(ovpndco_thread_data_idx, s);
        break;
    }

    case DLL_PROCESS_DETACH:
        if (ovpndco_thread_data_idx != TLS_OUT_OF_INDEXES)
        {
            /* Free thread local storage data and index. */
            free(TlsGetValue(ovpndco_thread_data_idx));
            TlsFree(ovpndco_thread_data_idx);
        }
        break;

    case DLL_THREAD_DETACH:
        /* Free thread local storage data. */
        free(TlsGetValue(ovpndco_thread_data_idx));
        break;
    }

    return TRUE;
}

