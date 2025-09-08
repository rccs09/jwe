package com.utils.jwe;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Base64;

import org.junit.Test;

public class SecretUtilsTest {

	@Test
	public void generateSecretHS256Test() {
		try {
			SecretUtils.generateSecretHS256();
			assertTrue(true);
		} catch (IOException e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}
	}

	@Test
	public void loadSecretHS256Test() {
		String secretName = "jwt-secret.b64";
		try {
			byte[] secret = SecretUtils.loadSecretHS256(secretName);
			String base64EncodedString = Base64.getEncoder().encodeToString(secret);
	        System.out.println(base64EncodedString); 
			assertTrue(true);
		} catch (Exception e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}
	}
	
	
}
