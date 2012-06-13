package com.trilead.ssh2.auth;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import com.google.code.juds.UnixDomainSocketClient;
import com.trilead.ssh2.packets.PacketAgentIdentitiesAnswer;
import com.trilead.ssh2.packets.PacketAgentRequestIdentities;
import com.trilead.ssh2.packets.PacketAgentSignRequest;
import com.trilead.ssh2.packets.PacketAgentSignResponse;
import com.trilead.ssh2.packets.TypesWriter;
import com.trilead.ssh2.signature.DSAPublicKey;

/**
 * A limited client for ssh-agent: it can only obtain public keys from it,
 * and let the agent sign messages.
 */
public class SshAgentClient {
    
    private final UnixDomainSocketClient socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    
    private final byte[][] blobs;
    private final Object[] keys;

    /**
     * Opens a socket connection to the ssh agent whose unix domain socket
     * name is specified in the SSH_AUTH_SOCK environment variable, and
     * extracts the stored public keys.
     * @throws NoAgentException is thrown when the client could not be
     *     created for some reason.
     */
    public SshAgentClient() throws NoAgentException {
	String socketName = System.getenv("SSH_AUTH_SOCK");
	if (socketName == null) {
	    throw new NoAgentException("No environment variable SSH_AUTH_SOCK");
	}
	try {
	    socket = new UnixDomainSocketClient(socketName, UnixDomainSocketClient.SOCK_STREAM);
	} catch (Throwable e) {
	    throw new NoAgentException("Connect to " + socketName + " failed", e);
	}
	in = new DataInputStream(socket.getInputStream());
	out = new DataOutputStream(socket.getOutputStream());
	PacketAgentRequestIdentities request = new PacketAgentRequestIdentities();
	byte[] payload = request.getPayload();

	try {
	    out.writeInt(payload.length);
	    out.write(payload);
	    out.flush();
	} catch (IOException e) {
	    try {
		socket.close();
	    } catch(Throwable e1) {
		// ignored
	    }
	    throw new NoAgentException("Write failed", e);
	}
	
	PacketAgentIdentitiesAnswer answer;
	
	try {
	    int len = in.readInt();
	    payload = new byte[len];
	    in.readFully(payload);
	    answer = new PacketAgentIdentitiesAnswer(payload, 0, payload.length);
	} catch (IOException e) {
	    try {
		socket.close();
	    } catch(Throwable e1) {
		// ignored
	    }
	    throw new NoAgentException("Read failed", e);
	}
	
	blobs = answer.getBlobs();
	keys = answer.getKeys();
    }
    
    public byte[] getBlob(int keyId) {
	TypesWriter tw = new TypesWriter();
	if (keys[keyId] instanceof DSAPublicKey) {
	    tw.writeString("ssh-dss");
	} else {
	    tw.writeString("ssh-rsa");
	}
	tw.writeString(blobs[keyId], 0, blobs[keyId].length);
	return tw.getBytes();
    }
    
    public String getType(int keyId) {
	if (keys[keyId] instanceof DSAPublicKey) {
	    return "ssh-dss";
	}
	return "ssh-rsa";
    }
    
    public int getNumKeys() {
	return blobs.length;
    }

    public byte[] generateSignature(byte[] msg, int keyId) throws IOException {
	PacketAgentSignRequest request = new PacketAgentSignRequest(msg, blobs[keyId]);
	byte[] payload = request.getPayload();

	out.writeInt(payload.length);
	out.write(payload);
	out.flush();

	PacketAgentSignResponse answer;

	int len = in.readInt();
	payload = new byte[len];
	in.readFully(payload);
	answer = new PacketAgentSignResponse(payload, 0, payload.length);
	return answer.getContents();	
    }

    public String getKey(int i) {
	return keys[i].toString();
    }

    public void close() {
	try {
	    socket.close();
	} catch(Throwable e) {
	    // ignored
	}
    }
}
