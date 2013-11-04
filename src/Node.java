import java.net.Inet6Address;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;

public class Node {
	public PublicKey public_key;
	public Inet6Address address;
	public int port;
	public long last_beacon;
	public KeyPair ephemeral_keys;
	public PublicKey their_ephemeral;
	public Key symmetric_key;
	public Chat chat;
	
	@Override
	public boolean equals(Object o) {
		if (o instanceof Node)
			return address.equals(((Node) o).address) && port == ((Node) o).port;
		return false;
	}
	
	public String long_string() {
		return String.format("[%s]:%d, last beacon %.1f seconds ago",
				address, port, (System.currentTimeMillis()-last_beacon)/1000.0);
	}
	
	public String short_string() {
		return String.format("[%s]:%d", address, port);
	}
	
	@Override
	public String toString() {
		return short_string();
	}
}
