package com.utils.jwt.client;

import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.utils.jwe.SecretUtils;

public class NimbusJwtClient {

	public static String generateJwtWithNimbus(String iss, String sub, String aud, long expSeconds, String secretSt) throws Exception{
		byte[] secret = SecretUtils.loadSecretHS256(secretSt);

        // Header tipico JWS
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT) // "typ":"JWT"
                .build();

        long now = System.currentTimeMillis();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(iss)
                .subject(sub)
                .audience(aud)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + expSeconds * 1000))
                .jwtID(UUID.randomUUID().toString())
                // .claim("scope", "wallet:read")
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new MACSigner(secret));  // HMAC-SHA256

        return jwt.serialize(); // header.payload.signature (Base64URL)
	}
	
}
