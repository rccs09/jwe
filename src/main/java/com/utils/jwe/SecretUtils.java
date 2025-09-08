package com.utils.jwe;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.Collectors;

public class SecretUtils {

	public static void generateSecretHS256() throws IOException {
		byte[] secret = new byte[32]; // 256 bits
        new SecureRandom().nextBytes(secret);

        File resources = new File("src/main/resources");
        if (!resources.exists()) resources.mkdirs();

        File out = new File(resources, "jwt-secret.b64");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
            // Base64 estándar (no URL) y en una sola línea
            w.write(Base64.getEncoder().encodeToString(secret));
        }
	}
	
	
	public static byte[] loadSecretHS256(String secretName) throws Exception {
		// 1) Prioriza variable de entorno (producción)
        String env = System.getenv("JWT_SHARED_SECRET_B64");
        if (env != null && !env.trim().isEmpty()) {
            return Base64.getDecoder().decode(env.trim());
        }

        // 2) Si no hay env, carga de resources (demo/dev)
        try (InputStream in = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream(secretName)) {
            if (in == null) throw new IllegalStateException("No se encontró "+secretName+" en resources");
            try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String b64 = br.lines().collect(Collectors.joining()).trim();
                return Base64.getDecoder().decode(b64);
            }
        } 
	}
	
}
