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

#include <Winsock2.h>
#include <Ws2tcpip.h>

#include <iostream>
#include <vector>
#include <cstdlib>

#include <NdisGuid.h>

#include <asio.hpp>

#include "..\uapi.h"

struct Transport {
	bool tcp;
	bool ipv6;
	std::string local_ip;
	int local_port;
	std::string remote_ip;
	int remote_port;
};

struct Tun {
	std::string vpn_ip;
	std::string vpn_netmask;
	std::string vpn_gw;
};

class OvpnCli
{
public:
	OvpnCli(const std::string dev_name, const Transport& transport, const Tun& tun, const std::string& key_file, int key_direction, asio::io_context& io_context)
		: io_context_(io_context)
	{
		HANDLE h = CreateFileA(dev_name.c_str(), GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
		if (h == INVALID_HANDLE_VALUE) {
			std::cerr << "CreateFileA(" << dev_name << ") failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}

		handle_ = std::make_unique<asio::windows::stream_handle>(io_context, h);

		new_peer(transport, [self = this, key_file, key_direction, tun]() {
			self->peer_added(key_file, key_direction, tun);
		});
	}

private:
	void peer_added(const std::string& key_file, int key_direction, const Tun& tun) {
		queue_read_();

		timer_ = std::make_unique<asio::steady_timer>(io_context_, duration_);
		timer_->async_wait([this](const asio::error_code& error) {
			tick_();
			});

		setup_crypto(key_file, key_direction);

		setup_keepalive();

		start_vpn();

		setup_tun(tun);
	}

	void start_vpn() {
		DWORD bytes_returned = 0;
		if (!DeviceIoControl(handle_->native_handle(), OVPN_IOCTL_START_VPN, NULL, 0, NULL, NULL, &bytes_returned, NULL)) {
			std::cerr << "DeviceIoControl(OVPN_IOCTL_START_VPN) failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}
	}

	void setup_keepalive() {
		OVPN_SET_PEER peer;
		peer.KeepaliveInterval = 10;
		peer.KeepaliveTimeout = 300;

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(handle_->native_handle(), OVPN_IOCTL_SET_PEER, &peer, sizeof(peer), NULL, NULL, &bytes_returned, NULL)) {
			std::cerr << "DeviceIoControl(OVPN_IOCTL_SET_PEER) failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}
	}

	// read key_file, get crypto keys/nonce and pass them to the driver
	void setup_crypto(const std::string& key_file, int key_direction) {
		if (key_file.length() == 0) {
			OVPN_CRYPTO_DATA crypto_data;
			ZeroMemory(&crypto_data, sizeof(crypto_data));
			crypto_data.CipherAlg = OVPN_CIPHER_ALG::OVPN_CIPHER_ALG_NONE;

			DWORD bytes_returned = 0;
			if (!DeviceIoControl(handle_->native_handle(), OVPN_IOCTL_NEW_KEY, &crypto_data, sizeof(crypto_data), NULL, NULL, &bytes_returned, NULL)) {
				std::cerr << "DeviceIoControl(OVPN_IOCTL_NEW_KEY) failed with code " << GetLastError() << std::endl;
				throw std::exception();
			}
			return;
		}

		HANDLE h = CreateFileA(key_file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (h == INVALID_HANDLE_VALUE) {
			std::cerr << "CreateFileA(" << key_file.c_str() << ") failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}

		constexpr int max_key_size = 4096;
		std::unique_ptr<char> buf_b64(new char[max_key_size]);
		DWORD bytes_read;
		if (!ReadFile(h, buf_b64.get(), max_key_size, &bytes_read, NULL)) {
			std::cerr << "ReadFile() failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}

		// base64 decode crypto keys/nonce
		DWORD bytes_required = 0;
		if (!CryptStringToBinaryA(buf_b64.get(), bytes_read, CRYPT_STRING_BASE64, NULL, &bytes_required, NULL, NULL)) {
			if (GetLastError() != ERROR_MORE_DATA) {
				std::cerr << "ReadFile() failed with code " << GetLastError() << std::endl;
				throw std::exception();
			}
		}

		std::unique_ptr<BYTE> buf(new BYTE[bytes_required]);
		if (!CryptStringToBinaryA(buf_b64.get(), bytes_read, CRYPT_STRING_BASE64, buf.get(), &bytes_required, NULL, NULL)) {
			std::cerr << "ReadFile() failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}

		OVPN_CRYPTO_DATA crypto_data;
		ZeroMemory(&crypto_data, sizeof(crypto_data));

		constexpr int key_len = sizeof(crypto_data.Encrypt.Key);

		if (key_direction) {
			CopyMemory(crypto_data.Encrypt.Key, buf.get() + key_len, key_len);
			CopyMemory(crypto_data.Decrypt.Key, buf.get(), key_len);
		}
		else {
			CopyMemory(crypto_data.Encrypt.Key, buf.get(), key_len);
			CopyMemory(crypto_data.Decrypt.Key, buf.get() + key_len, key_len);
		}

		crypto_data.Encrypt.KeyLen = key_len; // hardcode 256bit key size
		crypto_data.Decrypt.KeyLen = key_len; // hardcode 256bit key size

		constexpr int nonce_tail_len = sizeof(crypto_data.Encrypt.NonceTail);
		// for test purposes decrypt and encrypt nonces are same
		CopyMemory(crypto_data.Encrypt.NonceTail, buf.get() + key_len * 2, nonce_tail_len);
		CopyMemory(crypto_data.Decrypt.NonceTail, buf.get() + key_len * 2, nonce_tail_len);

		crypto_data.CipherAlg = OVPN_CIPHER_ALG::OVPN_CIPHER_ALG_AES_GCM;

		DWORD bytes_returned = 0;
		if (!DeviceIoControl(handle_->native_handle(), OVPN_IOCTL_NEW_KEY, &crypto_data, sizeof(crypto_data), NULL, NULL, &bytes_returned, NULL)) {
			std::cerr << "DeviceIoControl(OVPN_IOCTL_NEW_KEY) failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}
	}

	void setup_tun(const Tun& tun) {
		std::ostringstream ss;

		ss << "netsh interface ip set address \"Local Area Connection\" static " <<
			tun.vpn_ip << " " << tun.vpn_netmask << " " << tun.vpn_ip;
		std::string cmd = ss.str();
		std::cout << cmd;
		std::system(cmd.c_str());

		ss.str("");
		ss.clear();

		// decrease MTU so that payload and openvpn header wouldn't exceed physical network adapter MTU
		ss << "netsh interface ipv4 set subinterface \"Local Area Connection\" mtu=1428";
		cmd = ss.str();
		std::cout << cmd;
		std::system(cmd.c_str());

		ss.str("");
		ss.clear();

		// decrease MTU so that payload and openvpn header wouldn't exceed physical network adapter MTU
		ss << "netsh interface ipv6 set subinterface \"Local Area Connection\" mtu=1428";
		cmd = ss.str();
		std::cout << cmd;
		std::system(cmd.c_str());
	}

	void tick_() {
		//std::ostringstream os;
		//os << "hello, world " << index_ ++;
		//send_(os.str());

		OVPN_STATS stats;
		DWORD bytes_returned;
		if (!DeviceIoControl(handle_->native_handle(), OVPN_IOCTL_GET_STATS, NULL, 0, &stats, sizeof(OVPN_STATS), &bytes_returned, NULL)) {
			std::cerr << "DeviceIoControl(OVPN_IOCTL_GET_STATS) failed with code " << GetLastError() << std::endl;
			throw std::exception();
		}

		std::cout << "lostInCtrlPkts: " << stats.LostInControlPackets <<
			"\nlostInDataPkts: " << stats.LostInDataPackets <<
			"\nlostOutCtrlPkts: " << stats.LostOutControlPackets <<
			"\nlostOutDataPkts: " << stats.LostOutDataPackets <<
			"\nrcvdCtrlPkts: " << stats.ReceivedControlPackets <<
			"\nrcvdDataPkts: " << stats.ReceivedDataPackets <<
			"\nsentCtrlPkts: " << stats.SentControlPackets <<
			"\nsentDataPkts: " << stats.SentDataPackets <<
			"\ntransportBytesSent: " << stats.TransportBytesSent <<
			"\ntransportBytesReceived: " << stats.TransportBytesReceived <<
			"\ntunBytesSent: " << stats.TunBytesSent <<
			"\ntunBytesReceived: " << stats.TunBytesReceived << "\n\n";

		timer_->expires_at(timer_->expires_at() + duration_);
		timer_->async_wait([this](const asio::error_code& error) {
			tick_();
		});

		send_("hello, world!");
	};

	void queue_read_() {
		handle_->async_read_some(asio::buffer(buf, sizeof(buf)), [this](const asio::error_code& error, std::size_t bytes_transferred) {
			if (!error) {
				handle_read_(bytes_transferred);
			}
			else {
				std::cerr << "error " << error << " reading" << std::endl;
			}
		});
	}


	void handle_read_(size_t len) {
		//std::cout << "Received: " << buf << std::endl;
		//send_(std::string(buf));


		queue_read_();
	}

	void send_(const std::string& str) {
		handle_->write_some(asio::buffer(str.c_str(), str.length()));
	}

	template <class C>
	void new_peer(const Transport& transport, C callback) {
		OVPN_NEW_PEER peer = {};

		ADDRESS_FAMILY af = transport.ipv6 ? AF_INET6 : AF_INET;
		if (af == AF_INET6) {
			peer.Local.Addr6.sin6_family = af;
			inet_pton(af, transport.local_ip.c_str(), &(peer.Local.Addr6.sin6_addr));
			peer.Local.Addr6.sin6_port = htons(transport.local_port);

			peer.Remote.Addr4.sin_family = af;
			inet_pton(af, transport.remote_ip.c_str(), &(peer.Remote.Addr6.sin6_addr));
			peer.Remote.Addr6.sin6_port = htons(transport.remote_port);
		}
		else {
			peer.Local.Addr4.sin_family = af;
			inet_pton(af, transport.local_ip.c_str(), &(peer.Local.Addr4.sin_addr));
			peer.Local.Addr4.sin_port = htons(transport.local_port);

			peer.Remote.Addr4.sin_family = transport.ipv6 ? AF_INET6 : AF_INET;
			inet_pton(AF_INET, transport.remote_ip.c_str(), &(peer.Remote.Addr4.sin_addr));
			peer.Remote.Addr4.sin_port = htons(transport.remote_port);
		}

		peer.Proto = transport.tcp ? OVPN_PROTO_TCP : OVPN_PROTO_UDP;

		asio::windows::overlapped_ptr ov{ io_context_, [callback](const asio::error_code& ec, std::size_t len) {
			if (!ec) {
				std::cout << "TCP connected" << std::endl;
				callback();
			}
			else {
				std::cerr << "TCP connection error: " << ec.message() << std::endl;
				throw std::exception();
			}
		} };

		BOOL res = DeviceIoControl(handle_->native_handle(), OVPN_IOCTL_NEW_PEER, &peer, sizeof(peer), NULL, 0, NULL, ov.get());
		if (!res) {
			DWORD err = GetLastError();
			if (err == ERROR_IO_PENDING) {
				ov.release();
			}
			else {
				asio::error_code errCode(err, asio::system_category());
				ov.complete(errCode, 0);
			}
		}
		else {
			callback();
		}
	}

	std::unique_ptr<asio::windows::stream_handle> handle_;
	asio::io_context& io_context_;
	std::unique_ptr<asio::steady_timer> timer_;
	std::chrono::milliseconds duration_ = std::chrono::milliseconds(1000);

	char buf[4096];
	int index_ = 0;
};



int main(int argc, char **argv)
{
	if (argc < 10) {
		std::cout << "Usage: ovpn-dco-cli.exe <tcp|udp> <i4|i6> <local-ip> <local-port> <remote-ip> <remote-port> <vpn-ip> <vpn-netmask> <vpn-gw> <key-file> <key-direction>";
		return 1;
	}

	asio::io_context io_context;

	bool tcp = std::strcmp(argv[1], "tcp") == 0;
	bool ipv6 = std::strcmp(argv[2], "i6") == 0;
	Transport transport{ tcp, ipv6, argv[3], std::atoi(argv[4]), argv[5], std::atoi(argv[6]) };

	Tun tun{ argv[7], argv[8], argv[9] };

	std::string key_file;
	if (argc > 10)
		key_file = argv[10];

	int key_direction = 0;
	if (argc > 11)
		key_direction = std::atoi(argv[11]) > 0 ? 1 : 0;

	OvpnCli cli("\\\\.\\ovpn-dco", transport, tun, key_file, key_direction, io_context);
	io_context.run();

	return 0;
}
