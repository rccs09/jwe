package com.utils.jwt.client;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.utils.jwe.SecretUtils;

public class ManualJwtClient {
	
	public static String generateJwt(String iss, String sub, String aud, long expSeconds, String secretSt) throws Exception{
		byte[] secret = SecretUtils.loadSecretHS256(secretSt);
		
		long now = System.currentTimeMillis() / 1000L;
        String headerJson  = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		
        StringBuilder sbPayloadJson = new StringBuilder();
        sbPayloadJson.append("{")
        .append("\"iss\":\"").append(iss).append("\",")
        .append("\"sub\":\"").append(sub).append("\",")
        .append("\"aud\":\"").append(aud).append("\",")
        .append("\"iat\":").append(now).append(",")
        .append("\"exp\":").append((now + 300))
        .append("}");

        String headerB64  = b64u(headerJson.getBytes(StandardCharsets.US_ASCII));
        String payloadB64 = b64u(sbPayloadJson.toString().getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] sig = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));

        return signingInput + "." + b64u(sig);
	}
	
	private static String b64u(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
	
}
