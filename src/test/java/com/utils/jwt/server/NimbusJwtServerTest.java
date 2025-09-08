package com.utils.jwt.server;

import static org.junit.Assert.*;

import org.junit.Test;

import com.utils.jwt.client.ManualJwtClient;
import com.utils.jwt.client.NimbusJwtClient;

public class NimbusJwtServerTest {
	private static final String SECRET_NAME = "jwt-secret.b64";
	
	@Test
	public void verifyNimbusJwtGeneratedTest() {
		try {
			//Genero el JWT
			String jwt = NimbusJwtClient.generateJwtWithNimbus("Roberto", "Cadena", "Hola", 60, SECRET_NAME);
			
			//verifico jwt
			NimbusJwtServer.verify(jwt, "Roberto", "Hola", SECRET_NAME);
			assertTrue(true);
			
		} catch (Exception e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}
	}
	
	@Test
	public void verifyManualJwtGeneratedTest() {
		try {
			//Genero el JWT
			String jwt = ManualJwtClient.generateJwt("Roberto", "Cadena", "Hola", 60, SECRET_NAME);
			
			//verifico jwt
			NimbusJwtServer.verify(jwt, "Roberto", "Hola", SECRET_NAME);
			assertTrue(true);
			
		} catch (Exception e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}
	}

}
