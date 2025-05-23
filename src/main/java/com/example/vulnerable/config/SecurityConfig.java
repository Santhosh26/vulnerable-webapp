package com.example.vulnerable.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

@Configuration
public class SecurityConfig implements WebMvcConfigurer {
    
    // 19. Overly Permissive CORS (CWE-942)
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
            .allowedOrigins("*") // Too permissive
            .allowedMethods("*")
            .allowedHeaders("*")
            .allowCredentials(true); // Dangerous with wildcard origin
    }
    
    // 20. Hard-coded Encryption Key (CWE-321)
    private static final String ENCRYPTION_KEY = "ThisIsASecretKey";
    
    // 21. Use of Broken Crypto Algorithm (CWE-327)
    public String encrypt(String data) throws Exception {
        Key key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "DES"); // DES is broken
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // ECB mode is insecure
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return java.util.Base64.getEncoder().encodeToString(encrypted);
    }
    
    // 22. Insufficient Entropy (CWE-331)
    public String generateSessionId() {
        // Using predictable seed
        long seed = System.currentTimeMillis();
        return "SESSION_" + seed;
    }
}