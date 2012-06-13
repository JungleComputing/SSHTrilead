package com.trilead.ssh2.packets;

import java.io.IOException;

import com.trilead.ssh2.signature.DSASHA1Verify;
import com.trilead.ssh2.signature.RSASHA1Verify;

public class PacketAgentIdentitiesAnswer {
    
    // private final byte[] payload;
    private final int numKeys;
    private final byte[][] blobs;
    private final Object[] keys;

    // Only client side implemented.
    public PacketAgentIdentitiesAnswer(byte payload[], int off, int len) throws IOException {

	TypesReader tr = new TypesReader(payload, off, len);

	int packet_type = tr.readByte();
	if (packet_type != Packets.SSH2_AGENT_IDENTITIES_ANSWER) {
	    throw new IOException("This is not a SSH2_AGENT_IDENTITIES_ANSWER! (" + packet_type + ")");
	}

	numKeys = tr.readUINT32();
	blobs = new byte[numKeys][];
	keys = new Object[numKeys];
	for (int i = 0; i < numKeys; i++) {
	    blobs[i] = tr.readByteString();
	    tr.readByteString();			// skip comment
	    
	    try {
		keys[i] = DSASHA1Verify.decodeSSHDSAPublicKey(blobs[i]);
	    } catch(IllegalArgumentException e) {
		try {
		    keys[i] = RSASHA1Verify.decodeSSHRSAPublicKey(blobs[i]);
		} catch(IllegalArgumentException e1) {
		    throw new IOException("Don't understand answer from ssh agent");
		}
	    }
	}
    }
    
    public int getNumKeys() {
	return numKeys;
    }
    
    public byte[][] getBlobs() {
	return blobs;
    }
    
    public Object[] getKeys() {
	return keys;
    }
}
