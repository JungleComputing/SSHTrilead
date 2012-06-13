package com.trilead.ssh2.packets;

public class PacketAgentRequestIdentities
{
    byte[] payload;

    public PacketAgentRequestIdentities() {
    }

    public byte[] getPayload() {
	if (payload == null) {
	    TypesWriter tw = new TypesWriter();
	    tw.writeByte(Packets.SSH2_AGENTC_REQUEST_IDENTITIES);
	    payload = tw.getBytes();
	}
	return payload;
    }
}
