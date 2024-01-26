package com.scmp.security.auth;

import org.springframework.stereotype.Component;

@Component
public class AuthResponseService {
    public AuthenticationResponse createResponse(AuthStatus status, String accessToken, String refreshToken, String qrUri) {
        return AuthenticationResponse.builder()
                .status(status.getMessage())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .qrUri(qrUri)
                .build();
    }

    public AuthenticationResponse createResponse(AuthStatus status) {
        return AuthenticationResponse.builder()
                .status(status.getMessage())
                .accessToken(null)
                .refreshToken(null)
                .qrUri(null)
                .build();
    }
}
