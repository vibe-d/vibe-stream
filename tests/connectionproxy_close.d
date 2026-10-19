/+ dub.sdl:
	name "connectionproxy_close"
	description "Closing a ConnectionProxyStream must not disturb a pending read"
	dependency "vibe-stream" path=".."
+/
module app;

import core.time: msecs, seconds;

import vibe.core.core: runTask, sleep;
import vibe.core.net: TCPConnection, connectTCP, listenTCP;
import vibe.core.stream: ConnectionStream, Stream;
import vibe.internal.interfaceproxy: interfaceProxy;
import vibe.stream.wrapper: ConnectionProxyStream;

/**
	Closing a `ConnectionProxyStream` from one task while another task has a
	read pending on it used to abort the process.

	`close()` first invalidates the wrapped `TCPConnection` (the
	`m_socket == invalid` marker that the read completion in
	`TCPConnection.waitForDataEx` uses to detect a while-cancelled read),
	but then reset the embedded instance to `.init`, turning the marker into
	`{0, 0}`. The pending read completed by the close itself then hit
	`assert(sock == m_socket)` and took the whole process down.
*/
void main()
{
	// hold the accepted side open: dropping it would reset the connection
	// and wake the reader before the close we want to race with
	TCPConnection accepted;
	auto listener = listenTCP(0, (TCPConnection conn) nothrow { accepted = conn; }, "127.0.0.1");
	scope (exit) listener.stopListening();
	scope (exit) accepted.close();

	auto client = connectTCP("127.0.0.1", listener.bindAddress.port);

	auto proxy = new ConnectionProxyStream(
		interfaceProxy!Stream(client),
		interfaceProxy!ConnectionStream(client),
		true);

	auto reader = runTask(&readUntilClosed, proxy);

	// give the reader task time to park in a pending read
	sleep(100.msecs);

	// closing used to reset the embedded TCPConnection while the read was
	// still registered in the event loop - the completion then tripped
	// assert(sock == m_socket) in vibe.core.net
	proxy.close();

	reader.joinUninterruptible();
}

static void readUntilClosed(ConnectionProxyStream proxy) nothrow @safe
{
	ubyte[1024] buf;
	try {
		while (proxy.waitForData(5.seconds))
			proxy.read(buf);
	} catch (Exception) {
		// a read racing with the close may fail; the point here is that it
		// must not abort the process
	}
}
