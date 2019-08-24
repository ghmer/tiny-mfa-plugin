package de.whisperedshouts.identityiq.rest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.Base32;
import org.apache.log4j.Logger;

import sailpoint.api.SailPointContext;
import sailpoint.object.Capability;
import sailpoint.object.Identity;
import sailpoint.plugin.PluginBaseHelper;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.tools.GeneralException;

/**
 * This is a rest service used by the IdentityIQ TinyMFA plugin.
 * Its purpose is
 *  - To generate totp tokens for an identity
 *  - To supply the identity with a proper otpauth url (to be used in QRCodes)
 *  - To serve as a backend to verify tokens
 * 
 * @author Mario Ragucci
 *
 */
@Path("tiny-mfa")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class TinyMfaService extends BasePluginResource {
  //a logger object. Make use of it!
  public static final Logger _logger = Logger.getLogger(TinyMfaService.class);
  
  //this is the algorithm that is used to generate the rfc2104hmac hexstring
  public static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
  
  //this is the default, static width used in the dynamic truncation
  public static final int DYNAMIC_TRUNCATION_WIDTH = 4;
  
  //that big is our key to be
  public static final int FINAL_SECRET_SIZE = 16;
  
  //a format string for the qr code
  public static final String QR_CODE_FORMATSTRING          = "otpauth://totp/%1$s:%2$s@%1$s?algorithm=SHA1&digits=6&issuer=%1$s&period=30&secret=%3$s";
  
  //the SQL query used to retrieve the userkey from the database
  public static final String SQL_RETRIEVE_PASSWORD_QUERY   = "SELECT USERPASSWORD FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";
  
  //insert a new account into the database. This happens on first usage of the plugin
  public static final String SQL_CREATE_NEW_ACCOUNT_QUERY  = "INSERT INTO MFA_ACCOUNTS(ACCOUNT_NAME, USERPASSWORD, ISENCRYPTED) VALUES(?,?,?)";
  
  //insert a new validation attempt into the database
  public static final String SQL_INSERT_VALIDATION_ATTEMPT = "INSERT INTO MFA_VALIDATION_ATTEMPTS(ACCESS_TIME,CTS,ACCOUNT_NAME,SUCCEEDED) VALUES(?,?,?,?)";
  
  //check for failed validation attempts
  public static final String SQL_COUNT_VALIDATION_ATTEMPTS = "SELECT COUNT(*) FROM MFA_VALIDATION_ATTEMPTS WHERE CTS = ? and ACCOUNT_NAME = ? and SUCCEEDED = ?";
  
  //select unencrypted passwords from the database
  public static final String SQL_SELECT_UNENCRYPTED_PWS    = "SELECT ACCOUNT_NAME, USERPASSWORD, ISENCRYPTED FROM MFA_ACCOUNTS WHERE ISENCRYPTED = ?";
  
  //update password
  public static final String SQL_UPDATE_PASSWORD_FIELDS    = "UPDATE MFA_ACCOUNTS SET USERPASSWORD = ?, ISENCRYPTED = ? WHERE ACCOUNT_NAME = ?";
  
  // the capability to assign once a user shall be mfa activated
  public static final String CAPABILITY_NAME = "TinyMFAActivatedIdentity";

  @Override
  public String getPluginName() {
    return "tiny_mfa_plugin";
  }
  
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("getAppstoreLinks")
  public Response getAppstoreLinks() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s()", "getAppstoreLinks"));
    }
    
    String iosAppstoreLink     = PluginBaseHelper.getSettingString(getPluginName(), "mfaAppIos");
    String androidAppstoreLink = PluginBaseHelper.getSettingString(getPluginName(), "mfaAppAndroid");
    Map<String, String> result = new HashMap<>();
    
    result.put("iosAppstoreLink", iosAppstoreLink);
    result.put("androidAppstoreLink", androidAppstoreLink);
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getAppstoreLinks", result));
    }

    return Response.ok().entity(result).build();
  }
  
  /**
   * generates the appropriate totp url that is transferred within the
   * QRCode. This can be used with google authenticator.
   * If the account cannot be found in the database, it will be created
   * 
   * @return the application-url to send with the QRCode
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("generateQrCodeData")
  public Response getQrCodeData() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s()", "getQrCodeData"));
    }
    boolean hasError     = false;
    String qrCodeUrl     = null;
    String identityName  = null;
    String sanitizedName = null;
    String issuer        = PluginBaseHelper.getSettingString(getPluginName(), "issuerDomain");
    try {
      identityName = getLoggedInUserName();
      //sanitize the identityName;
      sanitizedName = java.net.URLEncoder.encode(identityName, "UTF-8");
      sanitizedName =  sanitizedName.replaceAll(" ", "%20");
    } catch (Exception e) {
      _logger.error(e.getMessage());
      hasError = true;
    }
    
    //no errors so far, continue with qrCodeUrl formatting
    if(!hasError) {
      String userPassword = null;
      try {
        SailPointContext context = getContext();
        userPassword             = returnPasswordFromDB(identityName, context);
        if(userPassword == null || userPassword.isEmpty()) {
          userPassword = createAccount(identityName, context);
        }
        
        //trim the password - IOS orders us to do so!
        userPassword = userPassword.substring(0, userPassword.indexOf("="));
        qrCodeUrl = String.format(QR_CODE_FORMATSTRING, issuer, sanitizedName, userPassword);
        
      } catch (Exception e) {
        _logger.error(e.getMessage());
        hasError = true;
      } 
      
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getQrCodeData", qrCodeUrl));
    }
    //return either an error or the qrCodeUrl
    return (hasError) ? Response.serverError().build() : Response.ok().entity(qrCodeUrl).build();
  }

  /**
   * validates a token for an identity
   * @param identityName the name of the account to check the token for
   * @param token the token to check
   * @return true whether the token could be validated
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("validateToken/{identityName}/{token}")
  public Boolean validateToken(@PathParam("identityName") String identityName, @PathParam("token") String token) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(identityName %s, token %s)", "validateToken", identityName, token));
    }
    
    //that's what we care for
    Boolean isAuthenticated = false;
    
    //get the maximum attempts from the plugin settings
    int maximumAllowedValidationAttempts = PluginBaseHelper.getSettingInt(getPluginName(), "maxAttempts");
    
    //get the current timestamp to generate the token
    long currentUnixTime    = getValidMessageBySystemTimestamp();
    
    //check for validation attempts, initialize with safety in mind
    int attemptsForTimestamp = maximumAllowedValidationAttempts + 1;
    try {
      attemptsForTimestamp = returnFailedValidationAttempts(identityName, currentUnixTime);
    } catch (GeneralException e1) {
      _logger.error(e1);
    } catch (SQLException e1) {
      _logger.error(e1);
    }
    
    if(attemptsForTimestamp < maximumAllowedValidationAttempts) {
      int generatedToken      = 0;
      //sanitize the token (just to be sure)
      int sanitizedToken      = TinyMfaService.sanitizeToken(token, 6);
      
      try {
        SailPointContext context = getContext();
        String userPassword      = returnPasswordFromDB(identityName, context);
        generatedToken           = TinyMfaService.generateValidToken(currentUnixTime, userPassword);
        
        //if codes match, you are welcome
        isAuthenticated = (generatedToken == sanitizedToken);
        
        //log the attempt
        insertValidationAttemptToDb(identityName, currentUnixTime, isAuthenticated);
      } catch (GeneralException | SQLException e) {
        _logger.error(e.getMessage());
      }
    } else {
      _logger.warn(String.format("number attempts (%s) exceeded limit %s for identity %s", attemptsForTimestamp, maximumAllowedValidationAttempts, identityName));
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "validateToken", isAuthenticated));
    }
    return isAuthenticated;
  }
  
  
  /**
   * validates a token for an identity. This method is not exposed via REST. Instead, it needs an existing SailPointContext to work
   * This method is used via reflection in the MFA workflow
   * @param identityName the name of the account to check the token for
   * @param token the token to check
   * @param context a SailPointContext to use
   * @return true whether the token could be validated
   */
  public Boolean validateToken(String identityName, String token, SailPointContext context) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(identityName %s, token %s)", "validateToken", identityName, token));
    }
    
    //that's what we care for
    Boolean isAuthenticated = false;
    
    //get the maximum attempts from the plugin settings
    int maximumAllowedValidationAttempts = PluginBaseHelper.getSettingInt(getPluginName(), "maxAttempts");
    
    //get the current timestamp to generate the token
    long currentUnixTime    = getValidMessageBySystemTimestamp();
    
    //check for validation attempts, initialize with safety in mind
    int attemptsForTimestamp = maximumAllowedValidationAttempts + 1;
    try {
      attemptsForTimestamp = returnFailedValidationAttempts(identityName, currentUnixTime);
    } catch (GeneralException e1) {
      _logger.error(e1);
    } catch (SQLException e1) {
      _logger.error(e1);
    }
    
    if(attemptsForTimestamp < maximumAllowedValidationAttempts) {
      int generatedToken      = 0;
      //sanitize the token (just to be sure)
      int sanitizedToken      = TinyMfaService.sanitizeToken(token, 6);
      
      try {
        String userPassword = returnPasswordFromDB(identityName, context);
        generatedToken = TinyMfaService.generateValidToken(currentUnixTime, userPassword);
        
        //if codes match, you are welcome
        isAuthenticated = (generatedToken == sanitizedToken);
        
        //log the attempt
        insertValidationAttemptToDb(identityName, currentUnixTime, isAuthenticated);
      } catch (GeneralException | SQLException e) {
        _logger.error(e.getMessage());
      }
    } else {
      _logger.warn(String.format("number attempts (%s) exceeded limit %s for identity %s", attemptsForTimestamp, maximumAllowedValidationAttempts, identityName));
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "validateToken", isAuthenticated));
    }
    return isAuthenticated;
  }
  
  /**
   * activates a token for an identity
   * @param identityName the name of the account to activate
   * @param token the token to use
   * @return true whether the token could be validated
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("activateToken/{identityName}/{token}")
  public Boolean activateToken(@PathParam("identityName") String identityName, @PathParam("token") String token) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(identityName %s, token %s)", "activateToken", identityName, token));
    }
    
    //that's what we care for
    Boolean isAuthenticated = validateToken(identityName, token);
    Identity identity       = null;
    Capability capability   = null;
    
    if(isAuthenticated) {
      SailPointContext context = getContext();
      try {
        identity = context.getObjectByName(Identity.class, identityName);
      } catch (GeneralException e) {
        _logger.error("Could not activate identity " + identityName + ": " + e.getMessage());
        isAuthenticated = false;
      }
    }
    
    if(identity !=  null) {
      SailPointContext context = getContext();
      try {
        capability = context.getObjectByName(Capability.class, CAPABILITY_NAME);
      } catch (GeneralException e) {
        _logger.error("Could not get capability " + CAPABILITY_NAME + ": " + e.getMessage());
        isAuthenticated = false;
      }
    }
    
    if(identity != null && capability != null) {
      SailPointContext context = getContext();
      try {
        identity.add(capability);
        context.saveObject(identity);
        context.commitTransaction();
      } catch (GeneralException e) {
        _logger.error("Could assign capability " + CAPABILITY_NAME + " to identity " + identityName + ": " + e.getMessage());
        isAuthenticated = false;
      }
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "activateToken", isAuthenticated));
    }
    return isAuthenticated;
  }
  
  /**
   * Encrypts unencrypted passwords on the database using the SailPoint encryption key
   * @return
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("encryptPasswords")
  public Response encryptPasswords() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s()", "encryptPasswords"));
    }
    int result       = 0;
    boolean hasError = false;
    
    try {
      Connection connection = getConnection();
      PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_SELECT_UNENCRYPTED_PWS);
      prepStatement.setBoolean(1, false);
      ResultSet rs = prepStatement.executeQuery();
      while(rs.next()) {
        String accountName = rs.getString(1);
        String password    = rs.getString(2);
        encryptPassword(accountName, password);
        result++;
      }
    } catch(Exception e) {
      _logger.error(e.getMessage());
      hasError = true;
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "encryptPasswords", result));
    }

    return (hasError) ? Response.serverError().build() : Response.ok().entity(result).build();
  }
  
  /**
   * encrypts a password using the SailPoint encryption key
   * @param accountName the accountName that identifies the dataentry to modify
   * @param password the password to be stored as an encrypted value
   * @throws Exception
   */
  private void encryptPassword(String accountName, String password) throws Exception {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(accountName %s, password %s)", "encryptPassword", accountName, password));
    }
    
    try {
      SailPointContext context = getContext();
      Connection connection    = getConnection();
      PreparedStatement preparedStatement = connection.prepareStatement(TinyMfaService.SQL_UPDATE_PASSWORD_FIELDS);
      String encryptedPassword = context.encrypt(password);
      preparedStatement.setString(1, encryptedPassword);
      preparedStatement.setString(2, "true");
      preparedStatement.setString(3, accountName);
      
      int resultCode = preparedStatement.executeUpdate();
      if(_logger.isDebugEnabled()) {
        _logger.debug("Update result code: " + resultCode);
      }
    } catch(Exception e) {
      _logger.error(e.getMessage());
      throw new Exception(e);
    }
    
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "encryptPassword", "void"));
    }
  }

  /**
   * Creates an account on the database
   * 
   * @param identityName the account to create
   * @param context a SailPointContext to use
   * @return the base32 encoded secretKey of the created account
   * @throws GeneralException
   * @throws SQLException
   */
  private String createAccount(String identityName, SailPointContext context) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "createAccount", identityName));
    }
    
    //generate a new secret key. User must not be bothered with this
    String generatedPassword = null;
    String encryptedPassword = null;
    if(shallEncryptPassword()) {
      generatedPassword = TinyMfaService.generateBase32EncodedSecretKey();
      encryptedPassword = context.encrypt(generatedPassword);
    } else {
      generatedPassword = TinyMfaService.generateBase32EncodedSecretKey();
    }
    
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_CREATE_NEW_ACCOUNT_QUERY);

    prepStatement.setString(1, identityName);
    if(shallEncryptPassword()) {
      prepStatement.setString(2, encryptedPassword);
      prepStatement.setString(3, "true");
    } else {
      prepStatement.setString(2, generatedPassword);
      prepStatement.setString(3, "false");
    }

    int resultCode = prepStatement.executeUpdate();
    if(resultCode != 0) {
    } else {
      throw new GeneralException("User could not be created");
    }

    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "createAccount", generatedPassword));
    }
    return generatedPassword;
  }
  
  /**
   * Calculates the hmac hash and returns its byteArray representation
   * 
   * @param data the message to hash (usually a timestamp)
   * @param key the secretKey to use
   * @return the byteArray representation of the calculated hmac
   * @throws SignatureException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
  private static byte[] calculateRFC2104HMAC(byte[] data, byte[] key)
      throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
    Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
    mac.init(signingKey);

    return mac.doFinal(data);
  }
  
  /**
   * Generates a new secretKey and encodes it to base32
   * @return the base32 encoded secretKey
   */
  private static String generateBase32EncodedSecretKey() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "generateBase32EncodedSecretKey"));
    }
    // Allocating the buffer
    byte[] buffer = new byte[128];

    // Filling the buffer with random numbers.
    new Random().nextBytes(buffer);

    // Getting the key and converting it to Base32
    Base32 codec        = new Base32();
    byte[] secretKey    = Arrays.copyOf(buffer, TinyMfaService.FINAL_SECRET_SIZE);
    byte[] bEncodedKey  = codec.encode(secretKey);
    String encodedKey   = new String(bEncodedKey);

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKey", encodedKey));
    }
    return encodedKey;
  }

  /**
   * generates a valid token for a timestamp and a base32 encoded secretKey
   * @param message the timestamp to use when calculating the token
   * @param key the base32 encoded secretKey
   * @return the current valid token for this key
   * @throws GeneralException
   */
  private static int generateValidToken(Long message, String key) throws GeneralException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(message %s, key %s)", "generateValidToken", message, key));
    }
    int token           = 0;
    byte[] keyBytes     = null;
    byte[] messageBytes = null;
    //let's process
    try {
      //the key is base32 encoded
      keyBytes      = new Base32().decode(key);
      //get an 8byte array derived from the message
      messageBytes  = TinyMfaService.longToByteArray(message, false);
      // generate the rfc2104hmac String out of timestamp and key
      byte[] rfc2104hmac = TinyMfaService.calculateRFC2104HMAC(messageBytes, keyBytes);
      
      //get the decimal representation of the last byte
      //this will be used as a offset. i.E if the last byte was 4 (as decimal), we will derive the 
      //dynamic trunacted result, starting at the 4th index of the byte array
      int offset = rfc2104hmac[(rfc2104hmac.length - 1)] & 0xF;
      if (_logger.isTraceEnabled()) {
        _logger.trace(String.format("using offset %d for dynamic truncation", (int) offset));
      }
      //probably int is too small (since there is no unsigned integer)
      //therefore, a long variable is used
      long dynamicTruncatedResult = 0;
      for (int i = 0; i < DYNAMIC_TRUNCATION_WIDTH; ++i) {
        //shift 8bit to the left to make room for the next byte
        dynamicTruncatedResult <<= 8;
        //perform a bitwise inclusive OR on the next offset
        //this adds the next digit to the dynamic truncated result
        dynamicTruncatedResult |= (rfc2104hmac[offset + i] & 0xFF);
      }

      //setting the most significant bit to 0
      dynamicTruncatedResult &= 0x7FFFFFFF;
      //making sure we get the right amount of numbers
      dynamicTruncatedResult %= 1000000;
      
      token = (int)dynamicTruncatedResult;

    } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
      _logger.error(e.getMessage(), e);
      throw new GeneralException(e.getMessage());
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateValidToken", token));
    }
    return token;
  }
  
  /**
   * returns a message based on a "corrected timestamp"
   * This method will get the current system time (Milliseconds since 1970),
   * then remove the seconds elapsed since the last half minute (i.E. 34 -> 30).
   * Last, we divide this by 30.
   * @return the message
   */
  private static long getValidMessageBySystemTimestamp() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s()", "getValidMessageBySystemTimestamp"));
    }
    long systemTime = System.currentTimeMillis();
    long message    = systemTime - (systemTime % 30);
    message         = (long) Math.floor(message / TimeUnit.SECONDS.toMillis(30));
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getValidMessageBySystemTimestamp", message));
    }
    return message;
  }

  /**
   * converts a long to a byteArray. You can choose whether the array shall be in reversed order
   * 
   * @param message the long to convert to a byteArray
   * @param reversed whether the array shall be reversed
   * @return the byteArray according to specification
   */
  private static byte[] longToByteArray(long message, boolean reversed) { 
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(message %s, reversed %s)", "longToByteArray", message, reversed));
    }

    //define the array
    byte[] data = new byte[8];
    long value = message;
    if(reversed) {
      for (int i = 0; i < 8; value >>>= 8) {
        data[i] = (byte) value;
        i++;
      }
    } else {
      for (int i = 8; i-- > 0; value >>>= 8) {
        data[i] = (byte) value;
      }
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "longToByteArray", data));
    }
    return data;
  }
  
  /**
   * Some minor sanitation efforts to make the string input more reliable
   * 
   * @param token the token to sanitize
   * @param desiredLength the desired length of the sanitized string
   * @return a sanitizes token
   */
  private static int sanitizeToken(String token, int desiredLength) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(token %s, desiredLength %s)", "sanitizeToken", token, desiredLength));
    }
    
    //return variable
    int result   = 0;
    //current position result variable
    int position = 0;
    
    //iterate over string characters
    for(int i = 0; i < token.length(); i++) {
      if(position >= desiredLength) {
        break;
      }
      //cast to byte
      byte b = (byte) token.charAt(i);
      switch(b) {
        case 32:  break; //space
        case 33:  b = 49; break; //exclamation mark to 1
        case 66:  b = 56; break; //capital B to 8
        case 71:  b = 54; break; //capital G to 6
        case 73:  b = 49; break; //capital I to 1
        case 79:  b = 48; break; //capital O to 0
        case 98:  b = 56; break; //smaller b to 8      
        case 103: b = 57; break; //smaller g to 9
        case 105: b = 49; break; //smaller i to 1
        case 111: b = 48; break; //smaller o to 0
      }
      
      //check if character is in allowed range
      if(b >= 48 && 57 >= b) {
        //add decimal representation of the character to the result variable
        result += b & 0xF;
        //raise position
        position++;
        //as long as we have not met the desired length, shift value to left
        if(position != desiredLength) {
          result *= 10;
        }
      }
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "sanitizeToken", result));
    }
    return result;
  }
  
  /**
   * returns the password for the given identityName
   * @param identityName the name of the identity
   * @param context a SailPointContext to use
   * @return the password of the identity
   * @throws GeneralException
   * @throws SQLException
   */
  private String returnPasswordFromDB(String identityName, SailPointContext context) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "returnPasswordFromDB", identityName));
    }
    String result = null;
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_RETRIEVE_PASSWORD_QUERY);

    prepStatement.setString(1, identityName);

    ResultSet rs = prepStatement.executeQuery();
    _logger.trace("query for pw executed");
    if (rs.next()) {
      if(shallEncryptPassword()) {
        String encryptedPassword = rs.getString(1);
        _logger.trace("got password " + encryptedPassword);
        _logger.trace("getting context");
        _logger.trace("decrypting");
        result = context.decrypt(rs.getString(1));
        _logger.trace("got decrypted pw " + result);
      } else {
        result = rs.getString(1);
      }
    }

    rs.close();
    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "returnPasswordFromDB", result));
    }
    return result;
  }
  
  /**
   * Inserts a validation attempt to the database
   * 
   * @param identityName the name of the account to query for
   * @param cts the corrected timestamp to query for
   * @return
   * @throws GeneralException
   * @throws SQLException
   */
  private boolean insertValidationAttemptToDb(String identityName, long cts, boolean succeeded) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s, cts %s, succeeded %s)", "insertValidationAttemptToDb", identityName, cts, succeeded));
    }
    
    boolean wasCompleted = false;
    
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_INSERT_VALIDATION_ATTEMPT);

    prepStatement.setDate(1, new java.sql.Date(new java.util.Date().getTime()));
    prepStatement.setString(2, identityName);
    prepStatement.setLong(3, cts);
    prepStatement.setBoolean(4, succeeded);

    int resultCode = prepStatement.executeUpdate();
    if(resultCode != 0) {
      wasCompleted = true;
    } 
    
    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "insertValidationAttemptToDb", wasCompleted));
    }
    return wasCompleted;
  }
  

  /**
   * Returns the number of failed validation attempts that have been made for the given identityName and corrected timestamp
   * 
   * @param identityName the name of the account to query for
   * @param cts the corrected timestamp to query for
   * @return the number of validation attempts for this identityName and cts
   * @throws GeneralException
   * @throws SQLException
   */
  private int returnFailedValidationAttempts(String identityName, long cts) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s, cts %s)", "returnFailedValidationAttempts", identityName, cts));
    }
    int result = 0;
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_COUNT_VALIDATION_ATTEMPTS);
  
    prepStatement.setString(1, identityName);
    prepStatement.setLong(2, cts);
    prepStatement.setBoolean(3, false);
  
    ResultSet rs = prepStatement.executeQuery();
    if (rs.next()) {
      result = rs.getInt(1);
    }
  
    rs.close();
    prepStatement.close();
    connection.close();
  
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "returnFailedValidationAttempts", result));
    }
    return result;
  }
  
  /**
   * returns whether the plugin is configured to encrypt passwords
   * @return true when configured to encrypt passwords
   */
  private boolean shallEncryptPassword() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "shallEncryptPassword"));
    }
    boolean shallEncrypt = false;
    shallEncrypt = PluginBaseHelper.getSettingBool(getPluginName(), "shallEncrypt");
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "shallEncryptPassword", shallEncrypt));
    }
    return shallEncrypt;
  }
}