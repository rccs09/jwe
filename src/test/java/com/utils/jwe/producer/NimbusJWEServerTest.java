package com.utils.jwe.producer;

import static org.junit.Assert.fail;

import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

import com.utils.jwe.PemUtils;
import com.utils.jwe.consumer.ManualJWEClient;
import com.utils.jwe.consumer.NimbusJWEClient;

public class NimbusJWEServerTest {

	@Test
	public void decryptCiphertextWithNimbusTest() {
		//Define el texto a cifrar
		String json = "{\"user\":\"roberto\",\"scope\":\"test\",\"doc\":123456789}";
		
		//Generar el JWE Compact “Con Nimbus"
		String tokenNimbus = null;
		try {
			//Cargar la clave pública desde resources
	        RSAPublicKey publicKey = PemUtils.loadPublicKeyFromResource("public.pem");
	        
	        //pruebo el cifrado
	        tokenNimbus = NimbusJWEClient.generateJweTokenWithNimbus(json, publicKey);
	        System.out.println("=== Token cifrado con Nimbus ===");
			System.out.println(tokenNimbus);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
		
		
        //decifro token manual
		try {
			String mensaje = NimbusJWEServer.decript(tokenNimbus);
	        System.out.println("=== Payload descifrado ===");
	        System.out.println(mensaje);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
	}
	
	@Test
	public void decryptCiphertextManuallyTest() {
		//Define el texto a cifrar
		String json = "{\"user\":\"roberto\",\"scope\":\"test\",\"doc\":123456789}";
		
		//Generar el JWE Compact manualmente
		String tokenManual = null;
		try {
			//Cargar la clave pública desde resources
	        RSAPublicKey publicKey = PemUtils.loadPublicKeyFromResource("public.pem");
	        
	        //pruebo el cifrado
	        tokenManual = ManualJWEClient.generateJweToken(json, publicKey);
	        System.out.println("=== Token cifrado Manualmente ===");
			System.out.println(tokenManual);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
		
		
        //decifro token manual
		try {
			String mensaje = NimbusJWEServer.decript(tokenManual);
	        System.out.println("=== Payload descifrado ===");
	        System.out.println(mensaje);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
	}

}
