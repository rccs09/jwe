package com.utils.jwt.server;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.utils.jwe.SecretUtils;

public class ManualJwtServer {
	public static boolean verify(String jwtString, String secretSt) throws Exception {
		byte[] secret = SecretUtils.loadSecretHS256(secretSt);
		
		String[] parts = jwtString.split("\\.");
        if (parts.length != 3) return false;

        String headerJson  = new String(b64uDec(parts[0]), StandardCharsets.US_ASCII);
        String payloadJson = new String(b64uDec(parts[1]), StandardCharsets.UTF_8);
        String signingInput = parts[0] + "." + parts[1];
        byte[] sigProvided = b64uDec(parts[2]);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] sigExpected = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));

        // comparación en tiempo constante
        boolean ok = java.security.MessageDigest.isEqual(sigProvided, sigExpected);
        System.out.println(ok ? "✅ Firma válida" : "❌ Firma inválida");
        if (ok) {
            System.out.println("=== Header (decodificado) ===");
            System.out.println(headerJson);
            System.out.println("=== Payload (decodificado) ===");
            System.out.println(payloadJson);
            // Aquí puedes parsear JSON y validar exp/iat/nbf/iss/aud, etc.
        }
        
        return ok;
	}
	
	private static byte[] b64uDec(String s) {
        return Base64.getUrlDecoder().decode(s);
    }
}
