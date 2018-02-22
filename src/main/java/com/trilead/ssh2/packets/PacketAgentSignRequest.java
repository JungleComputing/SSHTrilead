package com.trilead.ssh2.packets;

public class PacketAgentSignRequest {
    
    private byte[] payload = null;
    private final byte[] msg;
    private final byte[] blob;
    
    public PacketAgentSignRequest(byte[] msg, byte[] blob) {
	this.msg = msg;
	this.blob = blob;
    }
    
    public byte[] getPayload() {
	if (payload == null) {
	    TypesWriter tw = new TypesWriter();
	    tw.writeByte(Packets.SSH2_AGENTC_SIGN_REQUEST);
	    tw.writeString(blob, 0, blob.length);
	    tw.writeString(msg, 0, msg.length);
	    tw.writeUINT32(0);
	    payload = tw.getBytes();
	}
	return payload;
    }

}
