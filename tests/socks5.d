/+ dub.sdl:
	name "socks5_tests"
	description "SOCKS5 proxy connection test"
	dependency "vibe-stream:socks" path=".."
+/
module tests;

import core.time: seconds;
import std;
import vibe.core;
import vibe.core.sync: createTaskSemaphore;
// TODO: replace with toConnectionStreamInterface once that alias is added to vibe.core.stream.
import vibe.internal.interfaceproxy: asInterface;
import vibe.stream.counting;
import vibe.stream.semaphore;
import vibe.stream.socks;
import vibe.stream.wrapper: createConnectionProxyStream, createProxyStream;

void testRoundtrip(NetworkAddress proxy, string host, ushort target_port,
	string username = null, string password = null)
{
	auto tcp = connectTCP(proxy, anyAddress, 10.seconds);
	scope(exit) tcp.close();
	tcp.readTimeout = 10.seconds;

	auto conn = createSocks5Stream(tcp, host, target_port, username, password);
	scope(exit) conn.close();

	enforce(conn.connected, "SOCKS5 stream should report a connected state after the handshake.");

	ubyte[4] request = [1, 2, 3, 4];
	ubyte[4] response;

	conn.write(request[]);
	enforce(conn.waitForData(10.seconds), "SOCKS5 stream should report data as available for read.");
	conn.read(response[]);

	enforce(response[] == request[], "SOCKS5 round-trip returned corrupted data.");

	conn.close();
	enforce(!conn.connected, "Closed SOCKS5 stream must not report a connected state.");
}

void testEchoAddress(NetworkAddress proxy, NetworkAddress target)
{
	auto tcp = connectTCP(proxy, anyAddress, 10.seconds);
	scope(exit) tcp.close();
	tcp.readTimeout = 10.seconds;

	auto conn = createSocks5Stream(tcp, target);
	scope(exit) conn.close();

	enforce(conn.connected, "SOCKS5 stream should report a connected state after the handshake.");

	ubyte[4] request = [1, 2, 3, 4];
	ubyte[4] response;

	conn.write(request[]);
	enforce(conn.waitForData(10.seconds), "SOCKS5 stream should report data as available for read.");
	conn.read(response[]);

	enforce(response[] == request[], "SOCKS5 echo returned corrupted data.");

	conn.close();
	enforce(!conn.connected, "Closed SOCKS5 stream must not report a connected state.");
}

void testChainedRoundtrip(NetworkAddress proxy, string proxy_host, ushort proxy_port,
	string host, ushort target_port)
{
	auto tcp = connectTCP(proxy, anyAddress, 10.seconds);
	scope(exit) tcp.close();
	tcp.readTimeout = 10.seconds;

	// The first SOCKS5 layer tunnels to the proxy itself, so that the second
	// layer's handshake reaches the proxy through the already established
	// tunnel instead of the original TCP connection.
	auto outer = createSocks5Stream(tcp, proxy_host, proxy_port);
	scope(exit) outer.close();

	// The second SOCKS5 layer runs through the first one and reaches the target.
	auto inner = createSocks5Stream(outer, host, target_port);
	scope(exit) inner.close();

	ubyte[4] request = [1, 2, 3, 4];
	ubyte[4] response;

	inner.write(request[]);
	inner.read(response[]);

	enforce(response[] == request[], "Chained SOCKS5 round-trip returned corrupted data.");
}

private ConnectionStream countedLayer(ConnectionStream stream)
{
	auto input = stream.createLimitedInputStream(ulong.max);
	auto output = stream.createCountingOutputStream;
	return input.createConnectionProxyStream(output, stream);
}

private ConnectionStream proxiedLayer(ConnectionStream stream)
{
	return stream.createProxyStream.createConnectionProxyStream(stream);
}

private ConnectionStream semaphoreLayer(ConnectionStream stream)
{
	return asInterface!ConnectionStream(stream.createSemaphoreStream(createTaskSemaphore(1)));
}

void testDynamicChain(NetworkAddress proxy, string proxy_host, ushort proxy_port,
	string host, ushort target_port, size_t intermediate_hops)
{
	ubyte[4] request = [1, 2, 3, 4];
	ubyte[4] response;

	auto tcp = proxy.connectTCP(anyAddress, 10.seconds);
	scope(exit) tcp.close();
	tcp.readTimeout = 10.seconds;

	ConnectionStream current = asInterface!ConnectionStream(tcp.createSocks5Stream(proxy_host, proxy_port));

	foreach (_; 0 .. intermediate_hops)
		current = asInterface!ConnectionStream(current.countedLayer.createSocks5Stream(proxy_host, proxy_port));

	ConnectionStream conn = asInterface!ConnectionStream(current.proxiedLayer.semaphoreLayer
		.createSocks5Stream(host, target_port));
	scope(exit) conn.close();

	conn.write(request[]);
	conn.read(response[]);

	enforce(response[] == request[], "Dynamically built SOCKS5 chain returned corrupted data.");
}

void testStreamOnlyRoundtrip(NetworkAddress proxy, string host, ushort target_port)
{
	auto tcp = connectTCP(proxy, anyAddress, 10.seconds);
	scope(exit) tcp.close();
	tcp.readTimeout = 10.seconds;

	// A ProxyStream exposes only the Stream interface, without the connection
	// members, so this covers wrapping a non-ConnectionStream underlying.
	auto stream_only = createProxyStream(tcp);
	auto conn = createSocks5Stream(stream_only, host, target_port);
	static assert(!isConnectionStream!(typeof(conn)),
		"Socks5Stream must not claim connection semantics for a stream-only underlying.");

	ubyte[4] request = [1, 2, 3, 4];
	ubyte[4] response;

	conn.write(request[]);
	conn.read(response[]);

	enforce(response[] == request[], "SOCKS5 round-trip through a stream-only underlying returned corrupted data.");
}

// Builds a nested chain of SOCKS5 layers, each tunnelling through the previous
// one: every layer tunnels to the proxy itself, so the next layer's handshake
// travels through the already established tunnels, and only the innermost layer
// reaches the target.
void testSocks5ChainEcho(NetworkAddress proxy, string proxy_host, ushort proxy_port,
	string host, ushort target_port, size_t depth)
{
	ubyte[16] request = [0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x00, 0xFF, 0x7E, 0x81, 0x5A, 0xA5, 0x0F, 0xF0, 0x99, 0x66];
	ubyte[16] response;

	auto chain = proxy.connectTCP(anyAddress, 10.seconds)
		.createSocks5Stream(proxy_host, proxy_port)
		.createSocks5Stream(proxy_host, proxy_port)
		.createSocks5Stream(proxy_host, proxy_port)
		.createSocks5Stream(host, target_port);

	chain.write(request[]);
	chain.read(response[]);

	enforce(response[] == request[], "Echo through the nested SOCKS5 chain returned corrupted data.");
}

void main()
{
	auto proxy_host = environment.get("SOCKS5_PROXY_HOST", "127.0.0.1");
	auto proxy = resolveHost(proxy_host);
	proxy.port = environment.get("SOCKS5_PROXY_PORT", "1080").to!ushort;

	// listen on "::" so the target is reachable both via IPv4 and IPv6;
	// the proxy may resolve "localhost" to ::1 depending on the system
	auto echoServer = listenTCP(0, (conn) @safe nothrow {
		try {
			while (!conn.empty) {
				ubyte[4] buf;
				conn.read(buf[]);
				conn.write(buf[]);
			}
		} catch (Exception e) assert(false, e.msg);
	}, "::");
	scope(exit) echoServer.stopListening;

	auto echo_port = echoServer.bindAddress.port;

	logInfo("Testing SOCKS5 connection using an IPv4 literal");
	testRoundtrip(proxy, "127.0.0.1", echo_port);

	logInfo("Testing SOCKS5 connection using a domain name");
	testRoundtrip(proxy, "localhost", echo_port);

	logInfo("Testing SOCKS5 connection using an IPv4 address");
	auto target4 = resolveHost("127.0.0.1");
	target4.port = echo_port;
	testEchoAddress(proxy, target4);

	logInfo("Testing SOCKS5 connection using an IPv6 address");
	auto target6 = resolveHost("::1");
	target6.port = echo_port;
	testEchoAddress(proxy, target6);

	logInfo("Testing that a non-IP destination address is rejected");
	{
		auto tcp = connectTCP(proxy, anyAddress, 10.seconds);
		scope(exit) tcp.close();
		assertThrown(createSocks5Stream(tcp, NetworkAddress.init),
			"Expected a non-IP destination address to be rejected.");
	}

	logInfo("Testing chained SOCKS5 connections (SOCKS5 within SOCKS5)");
	testChainedRoundtrip(proxy, proxy_host, proxy.port, "127.0.0.1", echo_port);

	foreach (intermediate; 0 .. 3) {
		logInfo(format("Testing dynamically built SOCKS5 chain with %s intermediate hop(s)", intermediate));
		testDynamicChain(proxy, proxy_host, proxy.port, "127.0.0.1", echo_port, intermediate);
	}

	logInfo("Testing SOCKS5 connection with a stream-only underlying");
	testStreamOnlyRoundtrip(proxy, "127.0.0.1", echo_port);

	logInfo("Testing a nested SOCKS5 chain echo (four layers)");
	testSocks5ChainEcho(proxy, proxy_host, proxy.port, "127.0.0.1", echo_port, 4);

	auto user = environment.get("SOCKS5_USER", null);
	if (user.length) {
		logInfo("Testing SOCKS5 username/password authentication");
		auto auth_proxy = resolveHost(environment.get("SOCKS5_AUTH_HOST", "127.0.0.1"));
		auth_proxy.port = environment.get("SOCKS5_AUTH_PORT", "1081").to!ushort;
		testRoundtrip(auth_proxy, "127.0.0.1", echo_port, user, environment.get("SOCKS5_PASS", null));
	}

	logInfo("Testing SOCKS5 connection to an unreachable target");
	ushort closed_port;
	{
		auto tmp = listenTCP(0, (conn) @safe nothrow {}, "127.0.0.1");
		closed_port = tmp.bindAddress.port;
		tmp.stopListening();
	}
	auto tcp = connectTCP(proxy, anyAddress, 10.seconds);
	scope(exit) tcp.close();
	tcp.readTimeout = 10.seconds;
	assertThrown(createSocks5Stream(tcp, "127.0.0.1", closed_port),
		"Expected connecting to an unreachable target to fail.");

	logInfo("SOCKS5 test finished successfully.");
}
