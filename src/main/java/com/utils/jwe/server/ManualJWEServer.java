package com.utils.jwe.server;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import com.utils.jwe.PemUtils;

public class ManualJWEServer {
	// Tag de GCM es de 128 bits en JWE
    private static final int TAG_BITS = 128;
    
    public static String decript(String token) throws Exception  {
    	// 1) Cargar clave privada desde resources
        RSAPrivateKey privateKey = PemUtils.loadPrivateKeyFromResource("private.pem");

        // 2) Parsear las 5 partes del Compact JWE
        String[] parts = token.split("\\.");
        if (parts.length != 5) {
            throw new IllegalArgumentException("JWE Compact inválido: se esperaban 5 partes, llegaron " + parts.length);
        }
        String protectedHeaderB64u = parts[0];
        byte[] encryptedKey = b64uDecode(parts[1]);
        byte[] iv           = b64uDecode(parts[2]);
        byte[] ciphertext   = b64uDecode(parts[3]);
        byte[] tag          = b64uDecode(parts[4]);

        // 3) Decodificar header JSON (para validar alg/enc)
        String headerJson = new String(b64uDecode(protectedHeaderB64u), StandardCharsets.US_ASCII);
        String alg = getJsonString(headerJson, "alg");
        String enc = getJsonString(headerJson, "enc");
        if (alg == null || enc == null) {
            throw new IllegalArgumentException("Header JWE sin 'alg' o 'enc': " + headerJson);
        }

        // 4) Decifrar CEK(AES) con RSA-OAEP / RSA-OAEP-256
        byte[] cek = rsaOaepDecrypt(encryptedKey, privateKey, alg);

        // 5) AES-GCM: AAD = protected header B64URL en ASCII
        //    Java espera ciphertext||tag juntos para doFinal() en DECRYPT_MODE
        byte[] cipherAndTag = concat(ciphertext, tag);
        byte[] aad = protectedHeaderB64u.getBytes(StandardCharsets.US_ASCII);

        byte[] plaintext = aesGcmDecrypt(cek, iv, aad, cipherAndTag, enc);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /** Decrypt CEK with RSA-OAEP or RSA-OAEP-256 depending on 'alg'. */
    private static byte[] rsaOaepDecrypt(byte[] encrypted, RSAPrivateKey privateKey, String alg) throws Exception {
        final Cipher rsa;
        final OAEPParameterSpec spec;

        if ("RSA-OAEP-256".equalsIgnoreCase(alg)) {
            // Necesita soporte de "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" en tu JRE/JCE
            rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        } else if ("RSA-OAEP".equalsIgnoreCase(alg)) {
            // OAEP con SHA-1 (más compatible en Java 8)
            rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            spec = new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        } else {
            throw new IllegalArgumentException("alg no soportado: " + alg);
        }

        rsa.init(Cipher.DECRYPT_MODE, privateKey, spec);
        return rsa.doFinal(encrypted);
    }

    /** AES-GCM decrypt with AAD = Base64URL(protected header) ASCII bytes. */
    private static byte[] aesGcmDecrypt(byte[] cek, byte[] iv, byte[] aad, byte[] ciphertextAndTag, String enc) throws Exception {
        // Validar enc soportado
        if (!"A256GCM".equalsIgnoreCase(enc) && !"A128GCM".equalsIgnoreCase(enc)) {
            throw new IllegalArgumentException("enc no soportado: " + enc);
        }

        // Si tu JRE no tiene "unlimited strength" y la CEK es de 256 bits,
        // podrías ver InvalidKeyException en A256GCM.
        // Alternativas:
        //  - cambiar a A128GCM
        //  - instalar políticas unlimited (según tu distribución Java 8)

        SecretKeySpec key = new SecretKeySpec(cek, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BITS, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad); // AAD = protected header B64URL ascii
        }
        return cipher.doFinal(ciphertextAndTag); // ciphertext || tag
    }

    // -------- utilidades --------

    private static byte[] b64uDecode(String b64u) {
        return Base64.getUrlDecoder().decode(b64u);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // Extracción sencilla de un string del JSON del header (sin dependencias)
    private static String getJsonString(String json, String name) {
        // Busca: "name":"valor"
        Pattern p = Pattern.compile("\\\"" + Pattern.quote(name) + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }
}
