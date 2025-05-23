package com.example.vulnerable.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

@Service
public class FileService {
    
    // 23. Unrestricted File Upload (CWE-434)
    public String uploadFile(MultipartFile file) throws IOException {
        // No validation of file type or size
        String filename = file.getOriginalFilename();
        File dest = new File("/uploads/" + filename);
        file.transferTo(dest);
        return "File uploaded: " + filename;
    }
    
    // 24. Zip Slip vulnerability (CWE-22)
    public void extractZip(String zipFile) throws IOException {
        byte[] buffer = new byte[1024];
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
        ZipEntry zipEntry = zis.getNextEntry();
        
        while (zipEntry != null) {
            // Vulnerable: No path validation
            File newFile = new File("/extract/" + zipEntry.getName());
            
            FileOutputStream fos = new FileOutputStream(newFile);
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
            zipEntry = zis.getNextEntry();
        }
        zis.close();
    }
    
    // 25. Code Injection via Script Engine (CWE-94)
    public Object evaluateExpression(String expression) throws Exception {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        // Dangerous: evaluating user input
        return engine.eval(expression);
    }
    
    // 26. Resource Injection (CWE-99)
    public String readSystemFile(String filename) throws IOException {
        // User can specify any system file
        FileInputStream fis = new FileInputStream(filename);
        byte[] data = fis.readAllBytes();
        fis.close();
        return new String(data);
    }
    
    // 27. Uncontrolled Resource Consumption (CWE-400)
    public byte[] allocateMemory(int size) {
        // No limit on size - can cause DoS
        return new byte[size];
    }
    
    // 28. Use of Externally-Controlled Format String (CWE-134)
    public String formatLog(String userInput, Object... args) {
        // Dangerous if userInput contains format specifiers
        return String.format(userInput, args);
    }
}