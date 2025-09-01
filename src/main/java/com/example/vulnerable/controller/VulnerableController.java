package com.example.vulnerable.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.*;
import java.util.Random;
import java.security.MessageDigest;
import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // Hard-coded credentials (CWE-798)
    private static final String ADMIN_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";
    
    // 1. SQL Injection vulnerability (CWE-89)
    @GetMapping("/user")
    public String getUser(@RequestParam String id) {
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        return jdbcTemplate.queryForObject(query, String.class);
    }
    private boolean isValidHostname(String host){
        return host.matches("^[a-zA-Z0-9.-]+$");
    }
    // 2. Command Injection vulnerability (CWE-78)
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException {
        if (!isValidHostname(host))
        {
            throw new IllegalArgumentException("Invalid Hostname Detected, Probably a hack attempt");
        }
        String command = "ping -c 1 " + host;
        Process process = new ProcessBuilder(command).start();


        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // 3. Path Traversal vulnerability (CWE-22)
    @GetMapping("/file")
    public String readFile(@RequestParam String filename) throws IOException {
        String path = "/var/app/uploads/" + filename;
        return new String(Files.readAllBytes(Paths.get(path)));
    }
    
    // 4. Cross-Site Scripting (XSS) vulnerability (CWE-79)
    @GetMapping("/search")
    public String search(@RequestParam String query, HttpServletResponse response) {
        response.setContentType("text/html");
        return "<html><body>Search results for: " + query + "</body></html>";
    }
    
    // 5. XML External Entity (XXE) vulnerability (CWE-611)
    @PostMapping("/xml")
    public String processXml(@RequestBody String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Vulnerable: External entities are not disabled
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
        return doc.getDocumentElement().getTextContent();
    }
    
    // 6. Insecure Random Number Generation (CWE-330)
    @GetMapping("/token")
    public String generateToken() {
        Random random = new Random(); // Should use SecureRandom
        int token = random.nextInt(999999);
        return String.format("%06d", token);
    }
    
    // 7. Weak Cryptographic Hash (CWE-328)
    @PostMapping("/hash")
    public String hashPassword(@RequestParam String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // MD5 is weak
        byte[] hash = md.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
    
    // 8. Open Redirect vulnerability (CWE-601)
    @GetMapping("/redirect")
    public void redirect(@RequestParam String url, HttpServletResponse response) throws IOException {
        response.sendRedirect(url); // No validation
    }
    
    // 9. Insecure Deserialization (CWE-502)
    @PostMapping("/deserialize")
    public String deserialize(@RequestBody byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        Object obj = ois.readObject(); // Dangerous deserialization
        return obj.toString();
    }
    
    // 10. Information Exposure (CWE-200)
    @ExceptionHandler(Exception.class)
    public String handleError(Exception e) {
        // Exposing stack trace
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}