/**
	SOCKS5 proxy stream implementation

	Provides a way to establish a TCP connection through a SOCKS5 proxy.

	Copyright: © 2026 Denis Feklushkin
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
	Authors: Denis Feklushkin
*/
module vibe.stream.socks;

import vibe.core.net;
import vibe.core.stream;

import std.exception : enforce;
import std.format : format;
import std.socket : AddressFamily;

import core.time : Duration;

@safe:


/**
	Creates a SOCKS5 tunnel within an existing stream.

	The destination host name is passed to the proxy unchanged, so that the
	proxy performs the DNS resolution of the destination on its side.

	Instead of a host name with a separate port, the destination may also be
	passed as a prepared `NetworkAddress`; it is then sent to the proxy in
	binary IPv4 or IPv6 form, with the port taken from the address itself.

	The handshake is performed immediately when the stream is created, so that
	the returned stream can be used as a regular connection stream to the
	destination.

	Like a range, the returned stream wraps `underlying` by value and can in turn
	be passed as the `underlying` stream of another wrapper, so that arbitrary
	nested tunnels can be built.

	Params:
		underlying = The base stream which is used for the SOCKS5 tunnel
		hostname = Host name of the destination
		port = Port of the destination
		username = Optional user name (enables RFC 1929 username/password authentication)
		password = Optional password (enables RFC 1929 username/password authentication)
	Returns:
		A `Socks5Stream` that is tunneled through the proxy.
*/
auto createSocks5Stream(Stream)(Stream underlying, string hostname, ushort port,
	string username = null, string password = null)
	if (isStream!Stream)
{
	return Socks5Stream!Stream(underlying, hostname, port, username, password);
}

/// ditto
auto createSocks5Stream(Stream)(Stream underlying, NetworkAddress dest,
	string username = null, string password = null)
	if (isStream!Stream)
{
	return Socks5Stream!Stream(underlying, dest, username, password);
}


private enum Socks5Code : ubyte {
	Version = 0x05,
	AuthNone = 0x00,
	AuthUserPass = 0x02,
	AuthNotAcceptable = 0xFF,
	UserPassVersion = 0x01,
	CmdConnect = 0x01,
	RepSuccess = 0x00,
	AddrIPv4 = 0x01,
	AddrDomain = 0x03,
	AddrIPv6 = 0x04,
}


/** A stream that tunnels all I/O through a SOCKS5 proxy.

	The `Underlying` stream is stored by value and every operation is forwarded
	to it.
*/
struct Socks5Stream(Underlying) {
@safe:

	enum outputStreamVersion = 2;

	private Underlying m_connection;

	private this(Underlying underlying, string hostname, ushort port, string username, string password)
	{
		socks5Handshake(underlying, NetworkAddress.init, hostname, port, username, password);
		m_connection = underlying;
	}

	private this(Underlying underlying, NetworkAddress dest, string username, string password)
	{
		enforce(dest.family == AddressFamily.INET || dest.family == AddressFamily.INET6,
			"SOCKS5 destination address must be an IPv4 or IPv6 address.");

		socks5Handshake(underlying, dest, dest.toAddressString, dest.port, username, password);
		m_connection = underlying;
	}

	@property bool empty() { return m_connection.empty; }
	@property ulong leastSize() { return m_connection.leastSize; }
	@property bool dataAvailableForRead() { return m_connection.dataAvailableForRead; }
	const(ubyte)[] peek() { return m_connection.peek(); }

	size_t read(scope ubyte[] dst, IOMode mode) { return m_connection.read(dst, mode); }
	void read(scope ubyte[] dst) { auto n = read(dst, IOMode.all); assert(n == dst.length); }

	size_t write(scope const(ubyte)[] bytes, IOMode mode) { return m_connection.write(bytes, mode); }
	void write(scope const(ubyte)[] bytes) { auto n = write(bytes, IOMode.all); assert(n == bytes.length); }
	void write(scope const(char)[] bytes) { write(cast(const(ubyte)[])bytes); }

	void flush() { m_connection.flush(); }
	void finalize() { m_connection.finalize(); }

	static if (isConnectionStream!Underlying) {
		bool waitForData(Duration timeout = Duration.max) { return m_connection.waitForData(timeout); }
		@property bool connected() const { return m_connection.connected; }
		void close() { m_connection.close(); }
	}
}

mixin validateConnectionStream!(Socks5Stream!ConnectionStream);


private void socks5Handshake(Stream)(Stream stream, NetworkAddress dest,
	string hostname, ushort port, string username, string password)
	if (isStream!Stream)
{
	enforce(hostname.length > 0, "Destination host name must not be empty.");
	enforce(hostname.length <= 255, "Destination host name is too long for SOCKS5.");

	ubyte[] methods = username.length
		? [Socks5Code.Version, ubyte(2), Socks5Code.AuthUserPass, Socks5Code.AuthNone]
		: [Socks5Code.Version, ubyte(1), Socks5Code.AuthNone];
	stream.write(methods);

	ubyte[2] method_reply;
	stream.read(method_reply[]);
	enforce(method_reply[0] == Socks5Code.Version, "Invalid version in SOCKS5 method selection reply.");

	if (method_reply[1] == Socks5Code.AuthUserPass) {
		enforce(username.length > 0,
			"SOCKS5 proxy requested username/password authentication, but no credentials were supplied.");
		enforce(username.length <= 255, "SOCKS5 user name must not exceed 255 bytes.");
		enforce(password.length <= 255, "SOCKS5 password must not exceed 255 bytes.");

		auto auth = new ubyte[3 + username.length + password.length];
		auth[0] = Socks5Code.UserPassVersion;
		auth[1] = cast(ubyte)username.length;
		auth[2 .. 2 + username.length] = cast(const(ubyte)[])username;
		auth[2 + username.length] = cast(ubyte)password.length;
		auth[3 + username.length .. $] = cast(const(ubyte)[])password;
		stream.write(auth);

		ubyte[2] auth_reply;
		stream.read(auth_reply[]);
		enforce(auth_reply[0] == Socks5Code.UserPassVersion, "Invalid version in SOCKS5 authentication reply.");
		enforce(auth_reply[1] == Socks5Code.RepSuccess, "SOCKS5 proxy authentication failed.");
	} else {
		enforce(method_reply[1] == Socks5Code.AuthNone, method_reply[1] == Socks5Code.AuthNotAcceptable
			? "SOCKS5 proxy requires authentication, but no credentials were supplied."
			: format("SOCKS5 proxy requested unsupported authentication method 0x%02x.", method_reply[1]));
	}

	ubyte[4 + 1 + 255 + 2] request;
	size_t n = 0;
	request[n++] = Socks5Code.Version;
	request[n++] = Socks5Code.CmdConnect;
	request[n++] = 0x00; // reserved
	if (dest.family == AddressFamily.INET || dest.family == AddressFamily.INET6) {
		auto is_ipv4 = dest.family == AddressFamily.INET;
		request[n++] = is_ipv4 ? Socks5Code.AddrIPv4 : Socks5Code.AddrIPv6;
		auto ip_len = is_ipv4 ? size_t(4) : size_t(16);
		auto ip = () @trusted {
			auto p = is_ipv4
				? cast(const(ubyte)*)&dest.sockAddrInet4.sin_addr
				: cast(const(ubyte)*)&dest.sockAddrInet6.sin6_addr;
			return p[0 .. ip_len];
		} ();
		request[n .. n + ip_len] = ip;
		n += ip_len;
	} else {
		request[n++] = Socks5Code.AddrDomain;
		request[n++] = cast(ubyte)hostname.length;
		request[n .. n + hostname.length] = cast(const(ubyte)[])hostname;
		n += hostname.length;
	}
	request[n++] = cast(ubyte)(port >> 8);
	request[n++] = cast(ubyte)(port & 0xFF);
	stream.write(request[0 .. n]);

	ubyte[4] reply;
	stream.read(reply[]);
	enforce(reply[0] == Socks5Code.Version, "Invalid version in SOCKS5 reply.");
	enforce(reply[1] == Socks5Code.RepSuccess, format("SOCKS5 proxy failed to connect to %s:%s: %s",
		hostname, port, socks5ReplyDescription(reply[1])));
	enforce(reply[2] == 0x00, "Invalid reserved byte in SOCKS5 reply.");

	// consume the bound address, which we have no use for
	switch (reply[3]) {
		default:
			enforce(false, format("Invalid address type in SOCKS5 reply: 0x%02x.", reply[3]));
			break;

		case Socks5Code.AddrIPv4:
			ubyte[4 + 2] addr;
			stream.read(addr[]);
			break;

		case Socks5Code.AddrIPv6:
			ubyte[16 + 2] addr;
			stream.read(addr[]);
			break;

		case Socks5Code.AddrDomain:
			ubyte[1] len;
			stream.read(len[]);
			auto addr = new ubyte[len[0] + 2];
			stream.read(addr);
			break;
	}
}

private pure string socks5ReplyDescription(ubyte reply)
{
	switch (reply) {
		default: return format("unknown error 0x%02x", reply);
		case 0x01: return "general SOCKS server failure";
		case 0x02: return "connection not allowed by ruleset";
		case 0x03: return "network unreachable";
		case 0x04: return "host unreachable";
		case 0x05: return "connection refused";
		case 0x06: return "TTL expired";
		case 0x07: return "command not supported";
		case 0x08: return "address type not supported";
	}
}
