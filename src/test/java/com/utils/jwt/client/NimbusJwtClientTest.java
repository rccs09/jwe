package com.utils.jwt.client;

import static org.junit.Assert.*;

import org.junit.Test;

public class NimbusJwtClientTest {
	private static final String SECRET_NAME = "jwt-secret.b64";
	
	@Test
	public void generateJwtWithNimbusTest() {
		try {
			String jwt = NimbusJwtClient.generateJwtWithNimbus("Roberto", "Cadena", "Hola", 60, SECRET_NAME);
			assertNotNull(jwt);
			System.out.println(jwt);
		} catch (Exception e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}
	}

}
