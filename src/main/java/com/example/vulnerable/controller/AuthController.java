package com.example.vulnerable.controller;

import org.springframework.web.bind.annotation.*;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Hashtable;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/auth")
public class AuthController {
    
    // 11. LDAP Injection vulnerability (CWE-90)
    @PostMapping("/ldap-login")
    public boolean ldapLogin(@RequestParam String username, @RequestParam String password) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            
            DirContext ctx = new InitialDirContext(env);
            
            // Vulnerable LDAP query - no input sanitization
            String searchFilter = "(&(uid=" + username + ")(userPassword=" + password + "))";
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", 
                searchFilter, searchControls);
            
            return results.hasMore();
        } catch (Exception e) {
            return false;
        }
    }
    
    // 12. Session Fixation vulnerability (CWE-384)
    @PostMapping("/login")
    public String login(@RequestParam String username, 
                       @RequestParam String password,
                       HttpSession session) {
        // Not regenerating session ID after login
        if ("admin".equals(username) && "password".equals(password)) {
            session.setAttribute("user", username);
            return "Login successful";
        }
        return "Login failed";
    }
    
    // 13. Insufficient Session Expiration (CWE-613)
    @PostMapping("/logout")
    public String logout(HttpSession session) {
        // Not properly invalidating session
        session.removeAttribute("user");
        // Should call session.invalidate()
        return "Logged out";
    }
    
    // 14. Insecure Cookie without HttpOnly flag (CWE-1004)
    @GetMapping("/set-cookie")
    public String setCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("auth-token", "secret-value");
        // Missing HttpOnly and Secure flags
        response.addCookie(cookie);
        return "Cookie set";
    }
    
    // 15. Weak Password Requirements (CWE-521)
    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password) {
        // No password strength validation
        if (password.length() >= 3) { // Too weak
            // Store password (should be hashed)
            return "User registered";
        }
        return "Password too short";
    }
    
    // 16. Regular Expression Denial of Service (ReDoS) (CWE-1333)
    @PostMapping("/validate-email")
    public boolean validateEmail(@RequestParam String email) {
        // Vulnerable regex pattern
        String pattern = "^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\\]?)$";
        return Pattern.matches(pattern, email);
    }
    
    // 17. Missing Authorization Check (CWE-862)
    @DeleteMapping("/delete-user/{id}")
    public String deleteUser(@PathVariable String id) {
        // No authorization check - any user can delete any user
        // Should check if current user has permission
        return "User " + id + " deleted";
    }
    
    // 18. Timing Attack vulnerability (CWE-208)
    @PostMapping("/verify-token")
    public boolean verifyToken(@RequestParam String token) {
        String expectedToken = "secret-token-12345";
        // Vulnerable to timing attack
        return token.equals(expectedToken);
    }
}