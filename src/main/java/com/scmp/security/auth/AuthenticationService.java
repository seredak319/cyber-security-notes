package com.scmp.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.scmp.security.config.JwtService;
import com.scmp.security.token.Token;
import com.scmp.security.token.TokenRepository;
import com.scmp.security.token.TokenType;
import com.scmp.security.totp.TOTPUtil;
import com.scmp.security.user.Role;
import com.scmp.security.user.User;
import com.scmp.security.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Objects;

import static com.scmp.security.auth.AuthStatus.*;
import static com.scmp.security.auth.AuthUtils.simulateDelay;
import static com.scmp.security.totp.TOTPUtil.isSyntaxValidTotp;
import static com.scmp.security.totp.TOTPUtil.validateTOTP;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AuthResponseService authResponseService;

    @Value("${spring.application.name}")
    private static String issuer;

    public AuthenticationResponse register(RegisterRequest request) {
        log.info("Registering");
        simulateDelay(1000);

        if (!isValidRegisterRequest(request)) {
            return authResponseService.createResponse(BAD_DATA);
        }
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            return authResponseService.createResponse(ALREADY_REGISTERED);
        }

        try {
            final String totpSecret = TOTPUtil.generateTOTPSecret();
            var user = User.builder()
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .totpSecret(totpSecret)
                    .isAccountNonLocked(true)
                    .role(Role.USER)
                    .build();

            final String totpUri = TOTPUtil.generateTOTPURI(user.getUsername(), totpSecret, issuer);
            var savedUser = repository.save(user);
            var jwtToken = jwtService.generateToken(user);
            var refreshToken = jwtService.generateRefreshToken(user);
            saveUserToken(savedUser, jwtToken);
            return authResponseService.createResponse(SUCCESS, jwtToken, refreshToken, totpUri);
        } catch (Exception e) {
            return authResponseService.createResponse(FAILED);
        }
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        log.info("Authenticating");
        simulateDelay(1000);

        if (!isValidLoginRequest(request)) {
            return authResponseService.createResponse(BAD_DATA);
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
            final User user = repository.findByEmail(request.getEmail()).orElseThrow();

            if (!user.isAccountNonLocked()) {
                return authResponseService.createResponse(LOCKED);
            }

            if (isNotValidTotp(user, request.getTotpCode())) {
                if (user.isAccountNonLocked()) {
                    increaseLoginAttempts(user);
                    if (user.getLoginAttempts() > 4) {
                        user.setAccountNonLocked(false);
                        repository.save(user);
                        return authResponseService.createResponse(LOCKED);
                    } else {
                        return authResponseService.createResponse(NOT_SUCCESS);
                    }
                } else {
                    return authResponseService.createResponse(LOCKED);
                }
            }

            resetLoginAttempts(user);
            var jwtToken = jwtService.generateToken(user);
            var refreshToken = jwtService.generateRefreshToken(user);
            revokeAllUserTokens(user);
            saveUserToken(user, jwtToken);
            return AuthenticationResponse.builder()
                    .status(SUCCESS.getMessage())
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken)
                    .build();
        } catch (AuthenticationException e) {
            final User user = repository.findByEmail(request.getEmail()).orElse(null);

            if (user != null) {
                if (isNotValidTotp(user, request.getTotpCode())) {
                    if (user.isAccountNonLocked()) {
                        increaseLoginAttempts(user);
                        if (user.getLoginAttempts() > 4) {
                            user.setAccountNonLocked(false);
                            repository.save(user);
                            return authResponseService.createResponse(LOCKED);
                        }
                    } else {
                        return authResponseService.createResponse(LOCKED);
                    }
                }
            }

            log.info("failed Authentication");
            return authResponseService.createResponse(NOT_SUCCESS);
        }
    }

    private boolean isNotValidTotp(User user, String totpCode) {
        if (isSyntaxValidTotp(totpCode)) {
            final String totpSecret = user.getTotpSecret();
            if (!Objects.isNull(totpSecret)) {
                return !validateTOTP(totpCode, totpSecret);
            }
        }

        log.debug("User {} entered a non-valid TOTP", user.getEmail());
        return true;
    }

    private void increaseLoginAttempts(User user) {
        user.setLoginAttempts(user.getLoginAttempts() + 1);
        repository.save(user);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    private boolean isValidRegisterRequest(RegisterRequest request) {
        if (isBlank(request.getFirstname()) || isBlank(request.getLastname())
                || isBlank(request.getEmail()) || isBlank(request.getPassword())) {
            return false;
        }

        if (isAlphaCharactersOnly(request.getFirstname()) || isAlphaCharactersOnly(request.getLastname())) {
            return false;
        }

        if (request.getFirstname().length() < 2 || request.getLastname().length() < 2) {
            return false;
        }

        if (request.getEmail().length() < 8 || !isEmailValid(request.getEmail())) {
            return false;
        }

        return request.getPassword().length() >= 8;
    }

    private boolean isValidLoginRequest(AuthenticationRequest request) {
        if (isBlank(request.getEmail()) || isBlank(request.getPassword()) || isBlank(request.getTotpCode())) {
            return false;
        }

        if (request.getEmail().length() < 8 || !isEmailValid(request.getEmail()) || request.getTotpCode().length() < 6) {
            return false;
        }

        if (!isSyntaxValidTotp(request.getTotpCode())) {
            return false;
        }

        return request.getPassword().length() >= 8;
    }

    private void resetLoginAttempts(User user) {
        user.setLoginAttempts(0);
        repository.save(user);
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private boolean isAlphaCharactersOnly(String input) {
        return !input.matches("^[a-zA-Z]+$");
    }

    private boolean isEmailValid(String email) {
        return email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    }


}
