package com.utils.jwe.client;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.util.StandardCharset;

public class ManualJWEClient {
	// Configuración AES-GCM   ->  A256GCM => 256-bit key
    private static final int CEK_BITS = 256;
    // Tamanio del IV, recomendado por RFC: 96 bits (12 bytes)
    private static final int IV_BYTES = 12;
    // GCM Tag 128 bits (16 bytes)
    private static final int TAG_BITS = 128;          


    /**
	 * Cifra y genera el token JWE de un texto de forma manual
	 * @param plaintext - texto a cifrar
	 * @param rsaPublicKey - Clave publica
	 * @return
	 * @throws Exception - al ocurrir un error
	 */
    public static String generateJweToken(String plaintext, PublicKey rsaPublicKey) throws Exception {
    	//obtengo los bytes del texto a cifrar
    	byte[] plaintextByte = plaintext.getBytes(StandardCharset.UTF_8);
    	
    	//Define el header usando algoritmo:RSA-OAEP-256 y el tipo de encriptado:A256GCM
        String protectedHeaderJson = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
//    	String protectedHeaderJson = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}";
    	//Genera el base64 del header
        String protectedHeaderB64u = base64UrlNoPad(protectedHeaderJson.getBytes(StandardCharsets.US_ASCII));

        //Generar CEK (AES-256) y IV (12 bytes)
        SecretKey cek = generateAesKey(CEK_BITS);
        byte[] iv = randomBytes(IV_BYTES);

        //Cifra payload con AES/GCM/NoPadding, autenticando AAD = bytes US-ASCII de BASE64URL(protected header)
        AesGcmResult gcm = aesGcmEncrypt(cek.getEncoded(), iv, protectedHeaderB64u.getBytes(StandardCharsets.US_ASCII), plaintextByte);
        byte[] cipherText = gcm.ciphertext;
        byte[] tag = gcm.tag; // 16 bytes

        //llama al encriptado de la llave AES con RSA (llave publica)
        byte[] encryptedKey = rsaOaepEncrypt(cek.getEncoded(), rsaPublicKey);

        //Serializar Compact: 5 partes en Base64URL (sin padding)
        String ekB64u   = base64UrlNoPad(encryptedKey);
        String ivB64u   = base64UrlNoPad(iv);
        String ctB64u   = base64UrlNoPad(cipherText);
        String tagB64u  = base64UrlNoPad(tag);

        return protectedHeaderB64u + "." + ekB64u + "." + ivB64u + "." + ctB64u + "." + tagB64u;
    }

    //Cifra el texto con AES/GCM/NoPadding
    //El proceso de cifrado genera en un mismo arreglo el cifrado y el tag
    //Los divide y los asigna a un objeto para facilitar el manejo
    private static AesGcmResult aesGcmEncrypt(byte[] cekBytes, byte[] iv, byte[] aad, byte[] plaintext) throws Exception {
        SecretKeySpec key = new SecretKeySpec(cekBytes, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_BITS, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad); // AAD = BASE64URL(header) en ASCII, como indica el RFC
        }
        byte[] out = cipher.doFinal(plaintext);

        // En Java, out = ciphertext + tag  (tag al final)
        int tagBytes = TAG_BITS / 8;
        int ctLen = out.length - tagBytes;

        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[tagBytes];
        System.arraycopy(out, 0, ct, 0, ctLen);
        System.arraycopy(out, ctLen, tag, 0, tagBytes);

        return new AesGcmResult(ct, tag);
    }

    //Cifra la llave AES con RSA-OAEP (SHA-1, MGF1-SHA1) usando la llave publica RSA 
    private static byte[] rsaOaepEncrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        // Parámetros explícitos (equivalente al nombre de arriba)
        OAEPParameterSpec oaepSha1 = new OAEPParameterSpec(
                "SHA-1",
                "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT
        );
        rsa.init(Cipher.ENCRYPT_MODE, publicKey, oaepSha1);
        return rsa.doFinal(data);
    }

    //Genera clave AES de N bits.
    private static SecretKey generateAesKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(bits, new SecureRandom());
        return kg.generateKey();
    }

    //Bytes aleatorios seguros.
    private static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        new SecureRandom().nextBytes(out);
        return out;
    }

    //Base64URL sin padding, como exige JWE/JWT.
    private static String base64UrlNoPad(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    //Resultado de AES-GCM con campos separados.
    private static final class AesGcmResult {
        final byte[] ciphertext;
        final byte[] tag;
        AesGcmResult(byte[] ct, byte[] tag) {
            this.ciphertext = ct;
            this.tag = tag;
        }
    }
}
