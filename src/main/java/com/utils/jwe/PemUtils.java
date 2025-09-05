package com.utils.jwe;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

public class PemUtils {
	private PemUtils() {}
	
	/**
	 * Carga la llave publica a partir de un archivo PEM de llave publica ubicado en resources
	 * @param resourceName - nombre del archivo
	 * @return
	 * @throws Exception
	 */
	public static RSAPublicKey loadPublicKeyFromResource(String resourceName) throws Exception {
        String pem = readResourceAsString(resourceName);
        String normalized = stripPemHeaders(pem, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
        byte[] der = Base64.getMimeDecoder().decode(normalized);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }

	
	/**
	 * Carga la llave privada a partir de un archivo PEM de llave publica ubicado en resources
	 * @param resourceName - nombre del archivo
	 * @return
	 * @throws Exception
	 */
    public static RSAPrivateKey loadPrivateKeyFromResource(String resourceName) throws Exception {
        String pem = readResourceAsString(resourceName);
        String normalized = stripPemHeaders(pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        byte[] der = Base64.getMimeDecoder().decode(normalized);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }
    
    //Elimina las cabeceras PEM para obtner unicamente el valor de la llave
    private static String stripPemHeaders(String pem, String begin, String end) {
        String noBegin = pem.replace(begin, "");
        String noEnd = noBegin.replace(end, "");
        // Quita cualquier cosa que no sea Base64 (espacios, saltos de línea, \r, etc.)
        return noEnd.replaceAll("\\s", "");
    }

    //lee el contenido del archivo y lo retorna como texto
    private static String readResourceAsString(String resourceName) throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) cl = PemUtils.class.getClassLoader();

        try (InputStream in = cl.getResourceAsStream(resourceName)) {
            if (in == null) {
                throw new IllegalStateException("No se encontró el recurso en classpath: " + resourceName);
            }
            try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                return br.lines().collect(Collectors.joining("\n"));
            }
        }
    }
}
