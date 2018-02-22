package com.trilead.ssh2.auth;

public class NoAgentException extends Exception {

    public NoAgentException() {
    }

    public NoAgentException(String message) {
	super(message);
    }

    public NoAgentException(Throwable cause) {
	super(cause);
    }

    public NoAgentException(String message, Throwable cause) {
	super(message, cause);
    }
}
