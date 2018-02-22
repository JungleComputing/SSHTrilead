package com.trilead.ssh2.packets;

import java.io.IOException;

public class PacketAgentSignResponse {
    
    private final byte[] contents;

    public PacketAgentSignResponse(byte[] payload, int off, int len) throws IOException {
	
	TypesReader tr = new TypesReader(payload, off, len);

	int packet_type = tr.readByte();
	if (packet_type != Packets.SSH2_AGENT_SIGN_RESPONSE) {
	    throw new IOException("This is not a SSH2_AGENT_SIGN_RESPONSE! (" + packet_type + ")");
	}
	contents = tr.readByteString();
    }
    
    public byte[] getContents() {
	return contents;
    }
    
}
