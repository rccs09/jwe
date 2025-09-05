package com.utils.jwe;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class RSAKeyGenerator {
	//Longitud recomendada de la key RSA
	private static final int KEY_SIZE = 2048;
	
	/**
	 * Genera las key RSA publica y privada y las almacena en el path definido
	 */
	public static void generatePemOfPublicAndPriveteRSAKey(String pemFilePath) {
		try {
			// 1. Generar par de claves RSA
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(KEY_SIZE);
			KeyPair keyPair = keyGen.generateKeyPair();
			
			// 2. Obtener claves en formato DER (binario)
			byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
			byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
			
			// 3. Convertir a Base64 con formato PEM
			StringBuilder publicKeyPEMSb = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
			publicKeyPEMSb.append(chunkString(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKeyBytes)))
						  .append("\n-----END PUBLIC KEY-----");
			
			StringBuilder privateKeyPEMSb = new StringBuilder("-----BEGIN PRIVATE KEY-----\n");
			privateKeyPEMSb.append(chunkString(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privateKeyBytes)))
						   .append("\n-----END PRIVATE KEY-----");
			
			saveKeysAsFile(publicKeyPEMSb.toString(), privateKeyPEMSb.toString(), pemFilePath);
			
		} catch (Exception e) {
			System.out.println("No se pudo crear las key RSA");
			e.printStackTrace();
		}
	}
	
	//Guarda en PEM_FILE_PATH los archivos PEM de clave RSA privada y publica
	private static void saveKeysAsFile(String publicKeyPEM, String privateKeyPEM, String pemFilePath) throws UnsupportedEncodingException, FileNotFoundException, IOException {
		// Valida carpeta de destino
        File resourceDir = new File(pemFilePath);
        if (!resourceDir.exists()) {
            resourceDir.mkdirs();
        }
        
        // Crea los archivos pem en disco
        File pubFile = new File(resourceDir, "public.pem");
        File privFile = new File(resourceDir, "private.pem");

        //Escribe la data en los archivos
        try (Writer out = new OutputStreamWriter(new FileOutputStream(pubFile), "UTF-8")) {
            out.write(publicKeyPEM);
        }

        try (Writer out = new OutputStreamWriter(new FileOutputStream(privFile), "UTF-8")) {
            out.write(privateKeyPEM);
        }
	}
	
	// Utilidad para asegurar cortes de línea cada 64 caracteres
	private static String chunkString(String str) {
		return str.replaceAll("(.{64})", "$1\n");
	}
	
}
