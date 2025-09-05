package com.utils.jwe;

import static org.junit.Assert.*;

import org.junit.Test;

public class RSAKeyGeneratorTest {
	//path donde se almacenaran las keys como archivos PEM
	private static final String PEM_FILE_PATH = "src/test/resources";

	@Test
	public void generatePemOfPublicAndPriveteRSAKeyTest() {
		RSAKeyGenerator.generatePemOfPublicAndPriveteRSAKey(PEM_FILE_PATH);
		assertTrue(true);
	}

}
