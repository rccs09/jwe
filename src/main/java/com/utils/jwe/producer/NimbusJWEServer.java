package com.utils.jwe.producer;

import java.security.interfaces.RSAPrivateKey;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.util.StandardCharset;
import com.utils.jwe.PemUtils;

public class NimbusJWEServer {
	
	/**
	 * Decifra usando NIMBUS
	 * @param token token cifrado JWE
	 * @return
	 * @throws Exception
	 */
	public static String decript(String token) throws Exception{
		//Cargar la clave privada desde resources
        RSAPrivateKey privateKey = PemUtils.loadPrivateKeyFromResource("private.pem");
        //Parsear el JWE
        JWEObject jweObject = JWEObject.parse(token);

        //Descifrar con la clave privada
        RSADecrypter decrypter = new RSADecrypter(privateKey);
        jweObject.decrypt(decrypter);

        //Obtener el payload
        byte[] plaintext = jweObject.getPayload().toBytes();
        return new String(plaintext, StandardCharset.UTF_8);
	}
}
