package com.utils.jwe;

import static org.junit.Assert.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.Test;

public class PemUtilsTest {

	@Test
	public void loadPublicKeyFromResourceTest() {
		try {
			RSAPublicKey publicPk = PemUtils.loadPublicKeyFromResource("public.pem");
			assertNotNull(publicPk);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
	}
	
	@Test
	public void loadPrivateKeyFromResourceTest() {
		try {
			RSAPrivateKey privateKey = PemUtils.loadPrivateKeyFromResource("private.pem");
			assertNotNull(privateKey);
		} catch (Exception e) {
			fail("Not yet implemented");
		}
	}

}
