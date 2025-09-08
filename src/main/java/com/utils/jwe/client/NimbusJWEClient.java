package com.utils.jwe.client;

import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.StandardCharset;

public class NimbusJWEClient {
	
	/**
	 * Cifra y genera el token JWE de un texto usando Nimbus
	 * @param plaintext - texto a cifrar
	 * @param rsaPublicKey - Clave publica
	 * @return
	 * @throws Exception - al ocurrir un error
	 */
	public static String generateJweTokenWithNimbus(String plaintext, RSAPublicKey rsaPublicKey) throws Exception{
		//obtengo los bytes del texto a cifrar
		byte[] plaintextByte = plaintext.getBytes(StandardCharset.UTF_8);
		//Define el header usando algoritmo:RSA-OAEP-256 y el tipo de encriptado:A256GCM
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("application/json") // opcional: útil si tu payload es JSON
                .build();

        //Genera el Payload nimbus en base a texto que se desea cifrar
        Payload payload = new Payload(plaintextByte);

        //Construye el objeto JWE a partir del header y el payload
        JWEObject jweObject = new JWEObject(header, payload);

        //Define un encriptador con la llave prublica
        RSAEncrypter encrypter = new RSAEncrypter(rsaPublicKey);
        
        //En la siguiente linea Nimbus se encarga de:
        //1. Generar CEK (AES) de 256
		//2. Generar IV aleatorio para AES-GCM.
		//3. Cifra el payload con AES-GCM(CEK, IV) y calcula el Auth Tag autenticando el Protected Header (AAD).
		//4. Cifra la CEK AES con RSA-OAEP usando la clave pública
        jweObject.encrypt(encrypter);

        //Serializa el resultado como String (Compact Serialization)
        return jweObject.serialize();
	}
	
    
}
