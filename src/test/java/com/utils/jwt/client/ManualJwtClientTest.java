package com.utils.jwt.client;

import static org.junit.Assert.*;

import org.junit.Test;

public class ManualJwtClientTest {
	private static final String SECRET_NAME = "jwt-secret.b64";
	
	@Test
	public void generateJwtTest() {
		try {
			String jwt = ManualJwtClient.generateJwt("Roberto", "Cadena", "Hola", 60, SECRET_NAME);
			assertNotNull(jwt);
			System.out.println(jwt);
		} catch (Exception e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}
	}

}
