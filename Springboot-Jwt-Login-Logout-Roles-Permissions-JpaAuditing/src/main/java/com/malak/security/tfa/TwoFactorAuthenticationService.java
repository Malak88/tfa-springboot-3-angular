package com.malak.security.tfa;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TwoFactorAuthenticationService {
    // 3 methods

    // 1 Generate new Secret
    public String generateNewSecret() {
        return new DefaultSecretGenerator().generate();
    }
    // 2 Generate QR Code , Image URI
    public String generateQrCodeImageUri(String secret) {
        QrData data = new QrData.Builder()
                .label("Malak Coding 2FA example") // app name
                .secret(secret)
                .issuer("Malak Coding")
                .algorithm(HashingAlgorithm.SHA1) // increase security by sh256 or sh516
                .digits(6) //default = 6
                .period(30) // how long is valid  30 seconds
                .build();
        // Generate QR Code
        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = new byte[0]; // array to store generated code
        try {
            imageData = generator.generate(data);
        } catch (QrGenerationException e) {
            e.printStackTrace();
            log.error("Error while generating QR-CODE");
        }

        return Utils.getDataUriForImage(imageData, generator.getImageMimeType());
    }
    // 3 Validate the Code ?? QR

    // otp = one time password
    public boolean isOtpValid(String secret, String code) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();

        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        return verifier.isValidCode(secret, code);
    }

    public boolean isOtpNotValid(String secret, String code) {
        return !this.isOtpValid(secret, code);
    }
}
