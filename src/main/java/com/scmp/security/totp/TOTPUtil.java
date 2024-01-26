package com.scmp.security.totp;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Slf4j
public class TOTPUtil {

    public static String generateTOTPSecret() {
        DefaultSecretGenerator generator = new DefaultSecretGenerator();
        return generator.generate();
    }

    public static String generateTOTPURI(String username, String totpSecret, String issuer) {
        final QrData data = new QrData.Builder()
                .label(username)
                .secret(totpSecret)
                .issuer(issuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        final QrGenerator generator = new ZxingPngQrGenerator();

        try {
            final String mimeType = generator.getImageMimeType();
            final byte[] imageData = generator.generate(data);
            return getDataUriForImage(imageData, mimeType);
        } catch (QrGenerationException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean validateTOTP(String totpCode, String totpSecret) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        return verifier.isValidCode(totpSecret, totpCode);
    }

    public static boolean isSyntaxValidTotp(String totpCode) {
        return Pattern.compile("^\\d{6}$").matcher(totpCode).matches();
    }
}
