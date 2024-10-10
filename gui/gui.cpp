#include "..\uapi\ovpn-dco.h"

#include <windows.h>
#include <ws2tcpip.h>

#include <fstream>
#include <unordered_map>
#include <vector>
#include <string>
#include <utility>
#include <sstream>
#include <stdio.h>

#define DEV_NAME L"\\\\.\\ovpn-dco"
#define VER_DEV_NAME L"\\\\.\\ovpn-dco-ver"

#define BTN_SEND_CC 100

LRESULT CALLBACK WindowProcedure(HWND, UINT, WPARAM, LPARAM);

HWND hMPListenAddress, hMPListenPort,
    hP2PLocalAddress, hP2PLocalPort,
    hP2PRemoteAddress, hP2PRemotePort,
    hCCMessage, hCCRemoteAddress, hCCRemotePort,
    hMPNewPeerLocalIP, hMPNewPeerLocalPort, hMPNewPeerRemoteIP, hMPNewPeerRemotePort, hMPNewPeerVPNIP, hMPNewPeerPeerId,
    hNewKeyPeerId;

HWND hLogArea;
std::unordered_map<DWORD, std::wstring> buttons = {
    {OVPN_IOCTL_NEW_PEER, L"P2P New Peer"},
    {OVPN_IOCTL_GET_STATS, L"Get Stats"},
    {OVPN_IOCTL_NEW_KEY, L"New Key"},
    {OVPN_IOCTL_SWAP_KEYS, L"Swap Keys"},
    {OVPN_IOCTL_SET_PEER, L"Set Peer"},
    {OVPN_IOCTL_START_VPN, L"P2P Start VPN"},
    {OVPN_IOCTL_DEL_PEER, L"Del Peer"},
    {OVPN_IOCTL_GET_VERSION, L"Get Version"},
    {OVPN_IOCTL_NEW_KEY_V2, L"New Key V2"},
    {OVPN_IOCTL_SET_MODE, L"Set Mode"},
    {OVPN_IOCTL_MP_START_VPN, L"MP Start VPN"},
    {OVPN_IOCTL_MP_NEW_PEER, L"MP New Peer"},
    {OVPN_IOCTL_NEW_KEY, L"New Key"},
};

#define MIN_FUNCTION_CODE 1
#define MAX_FUNCTION_CODE 20

#define GET_IOCTL_FUNCTION_CODE(ioctl) (((ioctl) >> 2) & 0xFFF)

unsigned long GetIoctlFromFunctionCode(unsigned long functionCode) {
    return CTL_CODE(FILE_DEVICE_UNKNOWN, functionCode, METHOD_BUFFERED, FILE_ANY_ACCESS);
}

std::vector<std::pair<OVPN_MODE, std::wstring>> modeData = {
    {OVPN_MODE_P2P, L"P2P"},
    {OVPN_MODE_MP, L"MP"}
};

std::vector<HWND> hModes;

template <typename... Args>
void Log(Args... args) {
    std::wstringstream stream;

    // Using a fold expression to insert all arguments into the stream
    (stream << ... << args);

    // Move the caret to the end of the text
    int textLength = GetWindowTextLength(hLogArea);
    SendMessage(hLogArea, EM_SETSEL, (WPARAM)textLength, (LPARAM)textLength);

    // Add a newline character before the new text (if needed)
    std::wstring textToAppend = (textLength > 0 ? L"\r\n" : L"") + stream.str();

    // Insert the new text at the current caret position
    SendMessage(hLogArea, EM_REPLACESEL, FALSE, (LPARAM)textToAppend.c_str());
}

HANDLE hDev;
char readBuffer[4096] = {0};
OVERLAPPED ovRead = {0}, ovWrite = {0};

bool StartOverlappedRead() {
    ZeroMemory(readBuffer, sizeof(readBuffer));
    BOOL result = ReadFile(hDev, readBuffer, sizeof(readBuffer), NULL, &ovRead);
    if (!result && GetLastError() != ERROR_IO_PENDING) {
        Log("ReadFile failed: ", GetLastError());
        return false;
    }
    return true;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR args, int ncmdshow)
{
    // Create a Window Class
    WNDCLASSW wc = {0};

    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = hInst;
    wc.lpszClassName = L"myWindowClass";
    wc.lpfnWndProc = WindowProcedure;

    // Register the Window Class
    if (!RegisterClassW(&wc))
        return -1;

    // Create the Window
    HWND hwnd = CreateWindowW(L"myWindowClass", L"ovpn-dco-win GUI", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                              100, 100, 900, 600, NULL, NULL, NULL, NULL);

    HANDLE hEvRead = CreateEventW(NULL, FALSE, FALSE, NULL);
    ovRead.hEvent = hEvRead;

    HANDLE hEvWrite = CreateEventW(NULL, FALSE, FALSE, NULL);
    ovWrite.hEvent = hEvWrite;

    StartOverlappedRead();

    while (true) {
        HANDLE events[] = { hEvRead, hEvWrite };
        DWORD waitResult = MsgWaitForMultipleObjects(2, events, FALSE, INFINITE, QS_ALLINPUT);

        // read completed
        if (waitResult == WAIT_OBJECT_0) {
            DWORD bytesRead;
            if (GetOverlappedResult(hDev, &ovRead, &bytesRead, FALSE)) {
                if (bytesRead > 0) {
                    bool mp = SendMessage(hModes[1], BM_GETCHECK, 0, 0) == BST_CHECKED;

                    // if we're in server mode, we've received CC message prepended with sockaddr
                    if (mp) {
                        SOCKADDR_IN *sa = (SOCKADDR_IN *)readBuffer;

                        char ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(sa->sin_addr), ip, sizeof(ip));

                        int port = ntohs(sa->sin_port);

                        Log("CC[", ip, ":", port, "]> ", readBuffer + sizeof(*sa));
                    } else {
                        Log("CC[]> ", readBuffer);
                    }
                }
            } else {
                Log("Overlapped read failed: ", GetLastError());
            }

            if (!StartOverlappedRead()) {
                break;
            }
        } if (waitResult == WAIT_OBJECT_0 + 1) {
            // write completed
            DWORD bytesWrote;
            if (GetOverlappedResult(hDev, &ovWrite, &bytesWrote, FALSE)) {
                if (bytesWrote > 0) {
                    Log("Wrote ", bytesWrote, " bytes");
                }
            } else {
                Log("Overlapped write failed: ", GetLastError());
            }
        }
        else if (waitResult == WAIT_OBJECT_0 + 2) {
            // window messaging loop
            MSG msg;
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) {
                    CloseHandle(hDev);
                    CloseHandle(hEvRead);
                    CloseHandle(hEvWrite);
                    return 0;
                }
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }

    return 0;
}

void OpenDevice(const std::wstring& devName)
{
    hDev = CreateFileW(devName.c_str(), GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
    if (hDev == INVALID_HANDLE_VALUE) {
        Log(L"CreateFile(", devName, ") failed with code ", GetLastError());
    }
    else{
        Log(L"Device ", devName, " opened: ", hDev);
    }
}

void DcoGetVersion()
{
    // try version device
    HANDLE h = CreateFileW(VER_DEV_NAME, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        h = hDev;
    }

    OVPN_VERSION v{};
    DWORD bytesReturned;

    if (!DeviceIoControl(h, OVPN_IOCTL_GET_VERSION, NULL, 0, &v, sizeof(v), &bytesReturned, NULL)) {
        Log("DeviceIoControl(OVPN_IOCTL_GET_VERSION) failed with code ", GetLastError());
    }
    else {
        Log("Version: ", v.Major, ".", v.Minor, ".", v.Patch);
    }
}

void SetMode()
{
    OVPN_MODE m;

    if (SendMessage(hModes[0], BM_GETCHECK, 0, 0) == BST_CHECKED) {
        m = OVPN_MODE_P2P;
    } else {
        m = OVPN_MODE_MP;
    }

    DWORD bytesReturned;
    if (!DeviceIoControl(hDev, OVPN_IOCTL_SET_MODE, &m, sizeof(m), NULL, 0, &bytesReturned, NULL)) {
	    Log("DeviceIoControl(OVPN_IOCTL_SET_MODE) failed with code ", GetLastError());
    }
    else {
        Log("Mode set: ", m);
    }
}

// Function to convert sockaddr_in to a wstring containing IP and port
std::wstring sockAddrToString(const sockaddr_in& addr) {
    wchar_t ipAddress[INET_ADDRSTRLEN];  // Buffer to hold the IP address

    // Convert the binary IP address to a string (wide-char)
    InetNtopW(AF_INET, &(addr.sin_addr), ipAddress, INET_ADDRSTRLEN);

    // Convert the port number from network byte order to host byte order
    int port = ntohs(addr.sin_port);

    // Convert port to wstring and concatenate with IP address
    std::wstring result = ipAddress;
    result += L":";
    result += std::to_wstring(port);  // Append the port number

    return result;
}

void MPStartVPN()
{
    wchar_t ipAddress[16];  // Buffer to store IP address
    wchar_t portNumber[6];  // Buffer to store port number

    // Get the content of the IP address edit box
    GetWindowText(hMPListenAddress, ipAddress, 16);

    // Get the content of the port number edit box
    GetWindowText(hMPListenPort, portNumber, 6);

    // Initialize sockaddr_in structure
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;  // IPv4

    // Convert IP address string to binary form using InetPtonW
    InetPtonW(AF_INET, ipAddress, &(addr.sin_addr));

    // Convert port number string to integer and set it
    int port = _wtoi(portNumber);  // _wtoi for wide character conversion
    addr.sin_port = htons(port);  // Convert port to network byte order

    OVPN_MP_START_VPN in, out;
    in.ListenAddress.Addr4 = addr;

    DWORD bytesReturned;
    if (!DeviceIoControl(hDev, OVPN_IOCTL_MP_START_VPN, &in, sizeof(in), &out, sizeof(out), &bytesReturned, NULL)) {
        Log("DeviceIoControl(OVPN_IOCTL_MP_START_VPN) failed with code ", GetLastError());
    }
    else {
        Log("MP Start VPN: Listen on ", sockAddrToString(out.ListenAddress.Addr4));
    }
}

void P2PNewPeer()
{
    wchar_t localAddress[16], remoteAddress[16];
    wchar_t localPort[6], remotePort[6];

    GetWindowText(hP2PLocalAddress, localAddress, 16);
    GetWindowText(hP2PLocalPort, localPort, 6);
    GetWindowText(hP2PRemoteAddress, remoteAddress, 16);
    GetWindowText(hP2PRemotePort, remotePort, 6);

    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    InetPtonW(AF_INET, localAddress, &(localAddr.sin_addr));
    localAddr.sin_port = htons(_wtoi(localPort));

    sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    InetPtonW(AF_INET, remoteAddress, &(remoteAddr.sin_addr));
    remoteAddr.sin_port = htons(_wtoi(remotePort));

    OVPN_NEW_PEER newPeer;
    newPeer.Local.Addr4 = localAddr;
    newPeer.Remote.Addr4 = remoteAddr;
    newPeer.Proto = OVPN_PROTO_UDP;

    DWORD bytesReturned;
    if (!DeviceIoControl(hDev, OVPN_IOCTL_NEW_PEER, &newPeer, sizeof(newPeer), NULL, 0, &bytesReturned, NULL)) {
        Log("DeviceIoControl(OVPN_IOCTL_NEW_PEER) failed with code ", GetLastError());
    }
    else {
        Log("P2P peer added");
    }
}

void P2PStartVPN()
{
    DWORD bytesReturned;
    if (!DeviceIoControl(hDev, OVPN_IOCTL_START_VPN, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        Log("DeviceIoControl(OVPN_IOCTL_START_VPN) failed with code ", GetLastError());
    }
    else {
        Log("P2P VPN Started");
    }
}

void MPNewPeer()
{
    wchar_t localIP[16], localPort[6];
    wchar_t remoteIP[16], remotePort[6], vpnIP[16];
    wchar_t peerId[6];

    GetWindowText(hMPNewPeerLocalIP, localIP, 16);
    GetWindowText(hMPNewPeerLocalPort, localPort, 6);
    GetWindowText(hMPNewPeerRemoteIP, remoteIP, 16);
    GetWindowText(hMPNewPeerRemotePort, remotePort, 6);
    GetWindowText(hMPNewPeerVPNIP, vpnIP, 16);
    GetWindowText(hMPNewPeerPeerId, peerId, 6);

    sockaddr_in localAddr  = {};
    localAddr.sin_family = AF_INET;
    InetPtonW(AF_INET, localIP, &(localAddr.sin_addr));
    localAddr.sin_port = htons(_wtoi(localPort));

    sockaddr_in remoteAddr = {};
    remoteAddr.sin_family = AF_INET;
    InetPtonW(AF_INET, remoteIP, &(remoteAddr.sin_addr));
    remoteAddr.sin_port = htons(_wtoi(remotePort));

    in_addr vpnAddress;
    InetPtonW(AF_INET, vpnIP, &vpnAddress);

    OVPN_MP_NEW_PEER newPeer = {};
    newPeer.Local.Addr4 = localAddr;
    newPeer.Remote.Addr4 = remoteAddr;
    newPeer.VpnAddr4 = vpnAddress;
    newPeer.PeerId = _wtoi(peerId);

    DWORD bytesReturned;
    if (!DeviceIoControl(hDev, OVPN_IOCTL_MP_NEW_PEER, &newPeer, sizeof(newPeer), NULL, 0, &bytesReturned, NULL)) {
        Log("DeviceIoControl(OVPN_IOCTL_MP_NEW_PEER) failed with code ", GetLastError());
    }
    else {
        Log("MP peer added");
    }
}

void
NewKey()
{
    wchar_t peerId[6];
    GetWindowText(hNewKeyPeerId, peerId, 6);

    std::ifstream file("data64.key");
    if (!file) return;

    std::string b64str{(std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()};

    DWORD binarySize = 0;
    if (!CryptStringToBinaryA(b64str.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &binarySize, nullptr, nullptr))
        return;

    std::vector<BYTE> buf(binarySize);
    if (!CryptStringToBinaryA(b64str.c_str(), 0, CRYPT_STRING_BASE64, buf.data(), &binarySize, nullptr, nullptr))
        return;

    OVPN_CRYPTO_DATA crypto_data = {};
    constexpr int keyLen = sizeof(crypto_data.Encrypt.Key);

    bool mp = SendMessage(hModes[1], BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool keyDir = mp ? 1 : 0;
    if (keyDir) {
        CopyMemory(crypto_data.Encrypt.Key, buf.data() + keyLen, keyLen);
        CopyMemory(crypto_data.Decrypt.Key, buf.data(), keyLen);
    }
    else {
        CopyMemory(crypto_data.Encrypt.Key, buf.data(), keyLen);
        CopyMemory(crypto_data.Decrypt.Key, buf.data() + keyLen, keyLen);
    }

    crypto_data.Encrypt.KeyLen = keyLen; // hardcode 256bit key size
    crypto_data.Decrypt.KeyLen = keyLen; // hardcode 256bit key size

    constexpr int nonceTailLen = sizeof(crypto_data.Encrypt.NonceTail);
    // for test purposes decrypt and encrypt nonces are same
    CopyMemory(crypto_data.Encrypt.NonceTail, buf.data() + keyLen * 2, nonceTailLen);
    CopyMemory(crypto_data.Decrypt.NonceTail, buf.data() + keyLen * 2, nonceTailLen);

    crypto_data.CipherAlg = OVPN_CIPHER_ALG::OVPN_CIPHER_ALG_AES_GCM;
    crypto_data.PeerId = _wtoi(peerId);

    DWORD bytesReturned;
    if (!DeviceIoControl(hDev, OVPN_IOCTL_NEW_KEY, &crypto_data, sizeof(crypto_data), NULL, 0, &bytesReturned, NULL)) {
        Log("DeviceIoControl(OVPN_IOCTL_NEW_KEY) failed with code ", GetLastError());
    }
    else {
        Log("New key added");
    }
}

void
CreatePushButton(HWND hWnd, DWORD ioctl, int x, int y)
{
    CreateWindowW(L"Button", buttons[ioctl].c_str(), WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, x, y, 100, 30,
        hWnd, (HMENU)(INT_PTR)(GET_IOCTL_FUNCTION_CODE(ioctl)), NULL, NULL);
}

void
CreatePushButton(HWND hWnd, wchar_t* title, HMENU hMenu, int x, int y)
{
    CreateWindowW(L"Button", title, WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, x, y, 100, 30, hWnd, hMenu, NULL, NULL);
}

HWND
CreateEditBox(HWND hWnd, WCHAR* text, int x, int y, int width)
{
    return CreateWindowW(L"Edit", text, WS_VISIBLE | WS_CHILD | WS_BORDER | ES_LEFT, x, y, width, 20, hWnd, NULL, NULL, NULL);
}

void
SendCC()
{
    bool mp = SendMessage(hModes[1], BM_GETCHECK, 0, 0) == BST_CHECKED;

    sockaddr_in sa;
    char text[1024], remoteAddress[16], remotePort[6];
    GetWindowTextA(hCCMessage, text, 1024);
    GetWindowTextA(hCCRemoteAddress, remoteAddress, 16);
    GetWindowTextA(hCCRemotePort, remotePort, 6);

    char data[1024];
    DWORD dataLen = (DWORD)strlen(text);
    if (mp) {
        // in multipeer, we prepend CC message with sockaddr
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        InetPtonA(AF_INET, remoteAddress, &(sa.sin_addr));
        sa.sin_port = htons(atoi(remotePort));

        // prepend with sockaddr
        memcpy(data, &sa, sizeof(sa));
        memcpy(data + sizeof(sa), text, strlen(text));

        dataLen += sizeof(sa);
    } else {
        memcpy(data, text, strlen(text));
    }

    DWORD bytesWritten = 0;
    BOOL res = WriteFile(hDev, data, dataLen, &bytesWritten, &ovWrite);
    if (!res && GetLastError() != ERROR_IO_PENDING) {
        Log("WriteFile failed: ", GetLastError());
    }
}

// Window Procedure Function
LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        CreatePushButton(hwnd, OVPN_IOCTL_GET_VERSION, 10, 10);
        CreatePushButton(hwnd, OVPN_IOCTL_SET_MODE, 150, 10);

        for (auto i = 0; i < modeData.size(); ++i) {
            auto style = WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON;
            if (i == 0) style |= WS_GROUP;
            auto hMode = CreateWindowW(L"Button", modeData[i].second.c_str(), style,
                                        270 + 50 * i, 10, 50, 30, hwnd, (HMENU)(INT_PTR)(1000 + modeData[i].first), NULL, NULL);
            hModes.push_back(hMode);
        }

        CreatePushButton(hwnd, OVPN_IOCTL_MP_START_VPN, 10, 60);
        hMPListenAddress = CreateEditBox(hwnd, L"0.0.0.0", 150, 60, 120);
        hMPListenPort = CreateEditBox(hwnd, L"1194", 290, 60, 60);

        CreatePushButton(hwnd, OVPN_IOCTL_NEW_PEER, 10, 110);
        hP2PLocalAddress = CreateEditBox(hwnd, L"192.168.100.1", 150, 110, 120);
        hP2PLocalPort = CreateEditBox(hwnd, L"1194", 290, 110, 60);
        hP2PRemoteAddress = CreateEditBox(hwnd, L"192.168.100.2", 400, 110, 120);
        hP2PRemotePort = CreateEditBox(hwnd, L"1194", 540, 110, 60);

        CreatePushButton(hwnd, OVPN_IOCTL_START_VPN, 640, 110);

        CreatePushButton(hwnd, L"Send CC", (HMENU)BTN_SEND_CC, 10, 160);
        hCCMessage = CreateEditBox(hwnd, L"hello, dco-win", 150, 160, 120);
        hCCRemoteAddress = CreateEditBox(hwnd, L"192.168.100.1", 290, 160, 120);
        hCCRemotePort = CreateEditBox(hwnd, L"1194", 430, 160, 60);

        CreatePushButton(hwnd, OVPN_IOCTL_MP_NEW_PEER, 10, 210);
        hMPNewPeerLocalIP = CreateEditBox(hwnd, L"192.168.100.2", 150, 210, 120);
        hMPNewPeerLocalPort = CreateEditBox(hwnd, L"1194", 290, 210, 60);
        hMPNewPeerRemoteIP = CreateEditBox(hwnd, L"192.168.100.1", 400, 210, 120);
        hMPNewPeerRemotePort = CreateEditBox(hwnd, L"1194", 540, 210, 60);
        hMPNewPeerVPNIP = CreateEditBox(hwnd, L"10.8.0.6", 650, 210, 120);
        hMPNewPeerPeerId = CreateEditBox(hwnd, L"1", 790, 210, 60);

        CreatePushButton(hwnd, OVPN_IOCTL_NEW_KEY, 10, 260);
        hNewKeyPeerId = CreateEditBox(hwnd, L"1", 150, 260, 60);

        SendMessage(hModes[0], BM_SETCHECK, BST_CHECKED, 0);

        // log area
        hLogArea = CreateWindowW(L"Edit", L"",
                              WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
                              WS_VSCROLL | WS_HSCROLL | ES_READONLY,
                              0, 0, 600, 100, hwnd, (HMENU)3, NULL, NULL);

        OpenDevice(DEV_NAME);

        break;

    case WM_COMMAND:
    {
        if ((wp >= MIN_FUNCTION_CODE) && (wp < MAX_FUNCTION_CODE))
        {
            auto ioctl = GetIoctlFromFunctionCode((ULONG)wp);

            switch (ioctl) {
            case OVPN_IOCTL_GET_VERSION:
                DcoGetVersion();
                break;

            case OVPN_IOCTL_SET_MODE:
                SetMode();
                break;

            case OVPN_IOCTL_MP_START_VPN:
                MPStartVPN();
                break;

            case OVPN_IOCTL_NEW_PEER:
                P2PNewPeer();
                break;

            case OVPN_IOCTL_START_VPN:
                P2PStartVPN();
                break;

            case OVPN_IOCTL_MP_NEW_PEER:
                MPNewPeer();
                break;

            case OVPN_IOCTL_NEW_KEY:
                NewKey();
                break;
            }
        }
        else if ((ULONG)wp == BTN_SEND_CC) {
            SendCC();
        }

    }

        break;

    case WM_SIZE:
        {
            // Get the new width and height of the window
            int width = LOWORD(lp);
            int height = HIWORD(lp);

            // Resize the edit control (log area) to be at the bottom
            SetWindowPos(hLogArea, NULL, 0, height - 110, width, 100, SWP_NOZORDER);
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    return 0;
}