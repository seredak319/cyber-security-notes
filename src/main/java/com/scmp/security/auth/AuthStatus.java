package com.scmp.security.auth;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AuthStatus {

    SUCCESS("Success"),
    NOT_SUCCESS("Not Success"),
    FAILED("Failed"),
    ALREADY_REGISTERED("Already registered"),
    BAD_DATA("Bad data"),
    LOCKED("Locked");

    private final String message;
}
