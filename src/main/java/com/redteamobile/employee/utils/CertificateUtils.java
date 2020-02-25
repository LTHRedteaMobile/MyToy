package com.redteamobile.employee.utils;

import com.google.common.base.Strings;
import com.redteamobile.credential.CredentialUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Alex Liu
 * @date 2020/02/24
 */
public class CertificateUtils {
    private static final Logger logger = LoggerFactory.getLogger(CertificateUtils.class);

    public static PublicKey convertStringToPublicKey(String publicKeyString){
        if (Strings.isNullOrEmpty(publicKeyString)) {
            return null;
        }

        PublicKey publicKey = null;
        byte[] pubKeyBytes = Base64Utils.decodeFromString(publicKeyString);
        try {
            publicKey = CredentialUtils.decodePublicKey(pubKeyBytes);
        } catch (InvalidKeySpecException e) {
            logger.error("failed to convert publicKey , rootKeyID = {}" , publicKeyString);
        }
        return publicKey;
    }

    public static PrivateKey convertStringToPrivateKey(String privateKeyString){
        if (Strings.isNullOrEmpty(privateKeyString)) {
            return null;
        }

        PrivateKey privateKey = null;
        byte[] prvKeyBytes = Base64Utils.decodeFromString(privateKeyString);
        try {
            privateKey = CredentialUtils.decodePrivateKey(prvKeyBytes);
        } catch (InvalidKeySpecException e) {
            logger.error("failed to convert publicKey , rootKeyID = {}" , privateKeyString);
        }
        return privateKey;
    }
}
