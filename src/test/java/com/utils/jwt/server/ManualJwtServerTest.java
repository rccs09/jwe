package com.utils.jwt.server;

import static org.junit.Assert.*;

import org.junit.Test;

import com.utils.jwt.client.ManualJwtClient;

public class ManualJwtServerTest {
	private static final String SECRET_NAME = "jwt-secret.b64";

	@Test
	public void verifyManualJwtGeneratedTest() {
		try {
			//Genero el JWT
			String jwt = ManualJwtClient.generateJwt("Roberto", "Cadena", "Hola", 60, SECRET_NAME);
			
			//verifico jwt
			ManualJwtServer.verify(jwt, SECRET_NAME);
			assertTrue(true);
			
		} catch (Exception e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}
	}

}
