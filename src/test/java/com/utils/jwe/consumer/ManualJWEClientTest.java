package com.utils.jwe.consumer;

import static org.junit.Assert.*;

import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

import com.utils.jwe.PemUtils;
import com.utils.jwe.client.ManualJWEClient;

public class ManualJWEClientTest {

	@Test
	public void generateJweTokenTest() {
		//Define el texto a cifrar
		String json = "{\"user\":\"roberto\",\"scope\":\"test\",\"doc\":123456789}";
		
		try {
			//Cargar la clave pública desde resources
	        RSAPublicKey publicKey = PemUtils.loadPublicKeyFromResource("public.pem");
	        
	        //pruebo el cifrado
			String token = ManualJWEClient.generateJweToken(json, publicKey);
			System.out.println(token);
			assertNotNull(token);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
	}

}
