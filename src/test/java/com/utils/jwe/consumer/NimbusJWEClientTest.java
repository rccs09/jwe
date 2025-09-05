package com.utils.jwe.consumer;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

import com.utils.jwe.PemUtils;

public class NimbusJWEClientTest {
	
	@Test
	public void generateJweTokenWithNimbusTest() {
		//Define el texto a cifrar
		String json = "{\"user\":\"roberto\",\"scope\":\"test\",\"doc\":123456789}";
		
		try {
			//Cargar la clave pública desde resources
	        RSAPublicKey publicKey = PemUtils.loadPublicKeyFromResource("public.pem");
	        
	        //pruebo el cifrado
			String token = NimbusJWEClient.generateJweTokenWithNimbus(json, publicKey);
			System.out.println(token);
			assertNotNull(token);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
	}

}
