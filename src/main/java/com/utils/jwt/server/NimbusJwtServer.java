package com.utils.jwt.server;

import java.util.Date;
import java.util.List;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.utils.jwe.SecretUtils;

public class NimbusJwtServer {
	private static final long CLOCK_SKEW_SEC = 60L;
	
	public static void verify(String jwtString, String expectedIss, String expectedAud, String secretSt) throws Exception {
        byte[] secret = SecretUtils.loadSecretHS256(secretSt);
        SignedJWT jwt = SignedJWT.parse(jwtString);

        // valida firma HMAC
        boolean ok;
        try {
            ok = jwt.verify(new MACVerifier(secret));
        } catch (JOSEException e) {
            throw new JOSEException("Firma HS256 inválida", e);
        }
        if (!ok) throw new JOSEException("Firma HS256 inválida");

        // 2) claims
        JWTClaimsSet c = jwt.getJWTClaimsSet();
        Date now = new Date();

        if (c.getExpirationTime() == null || now.after(new Date(c.getExpirationTime().getTime() + CLOCK_SKEW_SEC * 1000))) {
            throw new IllegalStateException("Token expirado");
        }
        if (c.getIssueTime() != null && (now.getTime() + CLOCK_SKEW_SEC * 1000) < c.getIssueTime().getTime()) {
            throw new IllegalStateException("iat en el futuro");
        }
        if (c.getNotBeforeTime() != null && now.before(new Date(c.getNotBeforeTime().getTime() - CLOCK_SKEW_SEC * 1000))) {
            throw new IllegalStateException("nbf aún no alcanzado");
        }
        if (expectedIss != null && !expectedIss.equals(c.getIssuer())) {
            throw new IllegalStateException("issuer inesperado");
        }
        if (expectedAud != null) {
            List<String> aud = c.getAudience();
            if (aud == null || aud.stream().noneMatch(expectedAud::equals)) {
                throw new IllegalStateException("audience inesperada");
            }
        }

        System.out.println("✅ JWT válido. Claims:");
        System.out.println(c.toJSONObject());
    }
	
	
}
