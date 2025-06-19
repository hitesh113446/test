package com.aesaibuddy.controller;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.NamedNodeMap;

import com.aesaibuddy.dto.UserDto;
import com.aesaibuddy.dto.SSODto;
import com.aesaibuddy.dto.UserIdDto;
import com.aesaibuddy.dto.UserReducedDto;
import com.aesaibuddy.entity.UserEntity;
import com.aesaibuddy.exceptions.TokenNotValidException;
import com.aesaibuddy.exceptions.UserDoesnotExistException;
import com.aesaibuddy.repository.UserRepo;
import com.aesaibuddy.service.AuditLogService;
import com.aesaibuddy.service.LogoutServiceImpl;
import com.aesaibuddy.service.UserService;
import com.aesaibuddy.utils.Constants;
import com.aesaibuddy.utils.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;


import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletResponse;
import org.w3c.dom.*;
import javax.xml.parsers.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import com.aesaibuddy.service.SSOService;
import javax.servlet.http.Cookie;

@RestController
@RequestMapping("/aibuddy/user")
@CrossOrigin(origins = "${cors.origins}")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
     private UserRepo userRepo;

    @Autowired
    LogoutServiceImpl logoutService;
    @Autowired
 	private AuditLogService auditLogService;

    @Autowired
    private SSOService ssoService;
     
	public String actionUser="";

    @Value("${encryption.key}")
	private String encryptionKey; 

  	@Value("${encryption.iv}")
	private String encryptionIv;

    @PostMapping(value = "/authenticate", consumes = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE }, produces = {
            MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
    public ResponseEntity<String> authenticate(@RequestBody UserDto authRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getName(), authRequest.getPassword()));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        String jwtToken = jwtUtils.generateToken(authRequest.getName());
        return new ResponseEntity<>(jwtToken, HttpStatus.OK);
    }

    @GetMapping(value = "/token/validate", produces = { MediaType.APPLICATION_JSON_VALUE,
            MediaType.APPLICATION_XML_VALUE })
    public ResponseEntity<UserDto> isTokenValid(@RequestHeader("Authorization") String jwtToken) {
        return new ResponseEntity<>(userService.isTokenValid(jwtToken), HttpStatus.OK);
    }

    @PostMapping(value = "/register", consumes = { MediaType.APPLICATION_JSON_VALUE,
            MediaType.APPLICATION_XML_VALUE }, produces = { MediaType.APPLICATION_JSON_VALUE,
                    MediaType.APPLICATION_XML_VALUE })
    public ResponseEntity<String> registerUser(@RequestBody UserDto userdto) {
        return new ResponseEntity<>(userService.registerUser(userdto), HttpStatus.CREATED);
    }

    @GetMapping(value = "/role", produces = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
    public ResponseEntity<String> getRole(@RequestHeader("Authorization") String jwtToken) {
        UserDto status = userService.isTokenValid(jwtToken);
        String username = null;
        if (status != null) {
            username = jwtUtils.extractUsername(jwtToken);
        } else {
            throw new UserDoesnotExistException("User does not exist.");
        }
        return new ResponseEntity<>(userService.getRole(username), HttpStatus.OK);
    }

    @GetMapping("/get_users_id")
    public ResponseEntity<List<UserIdDto>> getAllUsersId() {
        List<UserIdDto> users = userService.getAllUsersId();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

 @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDto> loginUser(@RequestBody UserDto userDto) {
        log.info("Logging in user: {}", userDto.getEmail());
        String userName = userDto.getEmail();
        String password = userDto.getPassword();
        UserDto user = userService.findByEmail(userName);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
 
        
        if (user.isDeactivated()) {
        	log.warn("User account is deactivated: {}", userName);
                return new ResponseEntity<>(HttpStatus.LOCKED);
        }
        try {
            UserDetails userDetails = userService.loadUserByUsername(userName);
            String decryptedPassword = userDetails.getPassword();

 
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            if (!encoder.matches(password, decryptedPassword)) {
                log.error("Password mismatch for user: {}", userName);
                if(!user.getRole().equals("Admin")) {
                userService.increaseFailedAttempts(user);
                }
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            userService.resetFailedAttempts(userName);
            auditLogService.logAction(userName, "Logged In", "Authentication","","User Login Successful");
//            Authentication authenticate = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(userName, decryptedPassword));
            String jwt = jwtUtils.generateToken(userDetails.getUsername());
            UserDto userByName = userService.getUserByName(userName);
            userByName.setToken(jwt);
            userByName.setPassword("");
            actionUser=userByName.getEmail();
            return new ResponseEntity<UserDto>(userByName, HttpStatus.OK);
 
        } catch (Exception e) {
            log.error("Error occurred during login: {}", e.getMessage());
            return new ResponseEntity<UserDto>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping(value = "/add/user", produces = { MediaType.APPLICATION_JSON_VALUE,
            MediaType.APPLICATION_XML_VALUE })
    public ResponseEntity<String> createUser(@RequestBody UserDto userDto,@RequestHeader("Authorization") String token) {
	         return new ResponseEntity<>(userService.createUser(userDto,token), HttpStatus.OK);
    }

    @PostMapping(value = "/logout")
    public ResponseEntity<String> logoutUser(@RequestHeader("Authorization") String token,
            @RequestHeader("Role") String role) throws TokenNotValidException {
        try {
             UserDto userdto=userService.isTokenValid(token);
            auditLogService.logAction(userdto.getEmail(), "Logged Out", "Authentication",null,"User logged out");
	             return new ResponseEntity<String>(logoutService.logoutCheck(token, role, userdto.getEmail()), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<String>(HttpStatus.UNAUTHORIZED);
        }
    }

    
    @GetMapping("/get_users")
    public ResponseEntity<List<UserReducedDto>> getAllUsers() {
        List<UserReducedDto> users = userService.getAllUsers();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @GetMapping("/get_user/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable int id) {
        UserDto user = userService.getUserById(id);
        if (user != null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PutMapping("/update_user/{id}")
    public ResponseEntity<UserDto> updateUserById(@PathVariable int id, @RequestBody UserDto userDto,@RequestHeader("Authorization") String token) {
        try {
            UserDto updatedUser = userService.updateUserById(id, userDto,token);
            return new ResponseEntity<>(updatedUser, HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PutMapping("/update_status/{id}")
    public ResponseEntity<UserDto> updateUserStatus(@PathVariable int id,
            @RequestBody Map<String, String> requestBody, @RequestHeader("Authorization") String token) {
        try {
            String status = requestBody.get("status");
            UserDto updatedUser = userService.updateUserStatus(id, status, token);
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
    @GetMapping("/auth-type")
    public ResponseEntity<String> getAuthType(@RequestParam String email) {
        try {
            // Check if email exists
            if (!userRepo.existsByEmail(email)) {
                return new ResponseEntity<>("Email not found", HttpStatus.NOT_FOUND);
            }

            // Fetch user details
            UserEntity user = userRepo.findByEmail(email);

            // Return authType
            String authType = user.getAuthType();
            return new ResponseEntity<>(authType, HttpStatus.OK);
        } catch (Exception e) {
            // Handle unexpected errors
            return new ResponseEntity<>("Error occurred: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public String encrypt(String value) {
		try {

			// IvParameterSpec iv = new IvParameterSpec(Constants.IV.getBytes("UTF-8"));
			// SecretKeySpec skeySpec = new SecretKeySpec(Constants.KEY.getBytes("UTF-8"), "AES");

            IvParameterSpec iv = new IvParameterSpec(encryptionIv.getBytes("UTF-8")); 
			SecretKeySpec skeySpec = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

			byte[] encrypted = cipher.doFinal(value.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (Exception e) {
            System.out.println("Error Encrypting: " + e.getMessage());
		}
		return null;
	}

    public String decrypt(String encryptedValue) {
		try {
			// IvParameterSpec ivParameterSpec = new IvParameterSpec(Constants.IV.getBytes("UTF-8"));
			// SecretKeySpec secretKeySpec = new SecretKeySpec(Constants.KEY.getBytes("UTF-8"), "AES");

            IvParameterSpec ivParameterSpec = new IvParameterSpec(encryptionIv.getBytes("UTF-8")); 
			SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

			byte[] encryptedBytes = Base64.getDecoder().decode(encryptedValue);
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			return new String(decryptedBytes);
		} catch (Exception e) {
			System.out.println("Error Decrypting: " + e.getMessage());
		}
		return null;
	}


    @GetMapping("/ssopage")
    public void ssoLogin(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, HttpServletResponse response) throws IOException {
        // log.info("SSO Logging in user: {}", principal.getName());
        // String userName = principal.getName();
        log.info("Redirecting to SSO: {}");
        System.out.println("Redirecting to SSO");
       
    }
 
@PostMapping("/ssodashboard")
public void ssoDashboard(@RequestParam("SAMLResponse") String SAMLResponse, HttpServletResponse response) throws IOException {    try {
        // Step 1: Decode the SAML response (Base64)
        // String samlResponse = "BASE64_ENCODED_SAML_RESPONSE"; // Replace with actual SAML response
            System.out.println("SAmlREsponnse---------" +SAMLResponse);
            String decodedResponse = decodeSAMLResponse(SAMLResponse);
            String email = extractEmailFromSamlResponse(decodedResponse,ssoService);
            System.out.println("Email-------------" +email);
            if (email != null) {
                System.out.println("Extracted Email: " + email);
            } else {
                System.out.println("Email attribute not found in SAML response.");
            }
 
        // Step 3: Fetch user details from the database using the extracted email
        UserDto user = userService.findByEmail(email);
        if (user == null || !"SSO".equals(user.getAuthType())) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized access");
            return;
        }
 
        // Step 4: Generate JWT for the user
        UserDetails userDetails = userService.loadUserByUsername(email);
        String jwt = jwtUtils.generateToken(userDetails.getUsername());
 
        // Step 5: Prepare user object for frontend
        UserDto userByName = userService.getUserByName(email);
        userByName.setToken(jwt);
        userByName.setPassword(""); // Clear the password field
 
        // Step 6: Encrypt and encode the user details as JSON
        String jsonResponse = new ObjectMapper().writeValueAsString(userByName);
        String encryptedJsonResponse = encrypt(jsonResponse);
        String encodedJsonResponse = URLEncoder.encode(encryptedJsonResponse, "UTF-8");

        SSODto config = ssoService.getSSO(1);
        String entityId =config.getEntityId();

        // **Set encrypted data in an HTTP-only, secure cookie**
        Cookie ssoCookie = new Cookie("SSO_DATA", encryptedJsonResponse);
        ssoCookie.setHttpOnly(false);  // Prevents JavaScript access
        ssoCookie.setSecure(true);    // Ensures it is sent only over HTTPS
        ssoCookie.setPath("/");       // Makes it accessible site-wide
        ssoCookie.setMaxAge(60 * 5);  // Expiry time (5 minutes)
        response.addCookie(ssoCookie);

        // Step 7: Construct the redirect URL using entityId
        String redirectUrl = "http://" + entityId + "/sso";
 
        // Step 8: Redirect the user to the frontend with the encrypted data
        response.sendRedirect(redirectUrl);
 
    } catch (Exception e) {
        log.error("Error occurred during SAML response processing: {}", e.getMessage());
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Error during SAML response processing");
    }
}
 

    // Method to decode the Base64 SAML response
    public static String decodeSAMLResponse(String samlResponse) throws IllegalArgumentException {
        byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }

    // Method to extract email from the decoded SAML response
    public static String extractEmailFromSamlResponse(String samlResponse, SSOService ssoService) {
        try {
            // Convert string into InputStream for XML parsing
            InputStream is = new ByteArrayInputStream(samlResponse.getBytes(StandardCharsets.UTF_8));

            // Create a DocumentBuilderFactory and parse the SAML XML response
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true); // Enable namespace awareness
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(is);


            SSODto config = ssoService.getSSO(1);
            String emailAttributeName = config.getAttributeFormat();
            
            // Look for the email in the AttributeStatement
            NodeList attributeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
            for (int i = 0; i < attributeList.getLength(); i++) {
                Node attributeNode = attributeList.item(i);
                if (attributeNode instanceof Element) {
                    Element attributeElement = (Element) attributeNode;
                    String attributeName = attributeElement.getAttribute("Name");

                    // if ("email".equals(attributeName)) {
                        if (emailAttributeName.equals(attributeName)) {

                        NodeList valueList = attributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
                        if (valueList.getLength() > 0) {
                            return valueList.item(0).getTextContent(); // Return the email value
                        }
                    }
                }
            }

            return null; // Return null if no email found
        } catch (Exception e) {
            System.err.println("Error parsing SAML response: " + e.getMessage());
            return null;
        }
    }
}
