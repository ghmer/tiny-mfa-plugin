package de.whisperedshouts.identityiq.rest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
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

import sailpoint.plugin.PluginBaseHelper;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.tools.GeneralException;

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
  public static final String QR_CODE_FORMATSTRING = "otpauth://totp/%1$s:%2$s@%1$s?algorithm=SHA1&digits=6&issuer=%1$s&period=30&secret=%3$s";
  
  //the SQL query used to retrieve the userkey from the database
  public static final String SQL_RETRIEVE_PASSWORD_QUERY = "SELECT USERPASSWORD FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";
  
  //insert a new account into the database. This happens on first usage of the plugin
  public static final String SQL_CREATE_NEW_ACCOUNT_QUERY = "INSERT INTO MFA_ACCOUNTS(ACCOUNT_NAME, USERPASSWORD) VALUES(?,?)";

  //user exists query
  public static final String SQL_COUNT_ACCOUNT_NAME_QUERY = "SELECT COUNT(USERPASSWORD) FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME = ?";

  @Override
  public String getPluginName() {
    return "tiny-mfa-plugin";
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
    String issuer = PluginBaseHelper.getSettingString(getPluginName(), "issuerDomain");
    String identityName = null;
    try {
      identityName = getLoggedInUserName();
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    }
    
    boolean userExists = false;
    if(identityName != null) {
      try {
        userExists = returnCountForIdentityName(identityName);
      } catch (GeneralException | SQLException e) {
        _logger.error(e.getMessage());
      }
    }
    
    String userPassword = null;
    if(!userExists) {
      try {
        createAccount(identityName);
      } catch (Exception e) {
        _logger.error(e.getMessage());
      } 
    } 
    
    try {
      userPassword = returnPasswordFromDB(identityName);
    } catch (GeneralException | SQLException e) {
      _logger.error(e.getMessage());
    }
        
    String qrCodeUrl = String.format(QR_CODE_FORMATSTRING, issuer, identityName, userPassword);

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getQrCodeData", qrCodeUrl));
    }
    return Response.ok().entity(qrCodeUrl).build();
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

    //get the current timestamp to generate the token
    long currentUnixTime    = getValidUnixTimeStamp();
    int generatedToken      = 0;
    //sanitize the token (just to be sure)
    int sanitizedToken      = TinyMfaService.sanitizeToken(token);
    Boolean isAuthenticated = false;
    try {
      String userPassword = returnPasswordFromDB(identityName);
      generatedToken = TinyMfaService.generateValidToken(currentUnixTime, userPassword);
      
      //if codes match, you are welcome
      isAuthenticated = (generatedToken == sanitizedToken);

    } catch (GeneralException | SQLException e) {
      _logger.error(e.getMessage());
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "validateToken", isAuthenticated));
    }
    return isAuthenticated;
  }
  
  /**
   * Creates an account on the database
   * 
   * @param identityName the account to create
   * @return true whether the creation ended sucessfully
   * @throws GeneralException
   * @throws SQLException
   */
  private Boolean createAccount(String identityName) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "createAccount", identityName));
    }
    
    //generate a new secret key. User must not be bothered with this
    String generatedPassword = TinyMfaService.generateBase32EncodedSecretKey();
    
    Boolean result = false;
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_CREATE_NEW_ACCOUNT_QUERY);

    prepStatement.setString(1, identityName);
    prepStatement.setString(2, generatedPassword);

    int resultCode = prepStatement.executeUpdate();
    if(resultCode != 0) {
      result = true;
    }

    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "createAccount", result));
    }
    return result;
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
    // Notice: you want to reuse the same random generator
    // while generating larger random number sequences.
    new Random().nextBytes(buffer);

    // Getting the key and converting it to Base32
    Base32 codec = new Base32();
    byte[] secretKey = Arrays.copyOf(buffer, TinyMfaService.FINAL_SECRET_SIZE);
    byte[] bEncodedKey = codec.encode(secretKey);
    String encodedKey = new String(bEncodedKey);

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
      //the key is base32 encoded - that's a google thingy
      keyBytes      = new Base32().decode(key);
      //get a reversed 8byte array
      messageBytes  = TinyMfaService.longToByteArray(message, 8, true);
      // generate the rfc2104hmac String out of timestamp and key
      byte[] rfc2104hmac = TinyMfaService.calculateRFC2104HMAC(messageBytes, keyBytes);
      
      //get the decimal representation of the last byte
      //this will be used as a offset. i.E if the last byte was 4, we will derive the 
      //dynamic trunacted result, starting at the 4th index of the byte array
      int offset = rfc2104hmac[20 - 1] & 0xF;
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
   * returns a "corrected" timestamp of the system.
   * @return the timestamp
   */
  private static long getValidUnixTimeStamp() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s()", "getValidUnixTimeStamp"));
    }
    long systemTime = System.currentTimeMillis();
    long unixTime = systemTime - (systemTime % 30);
    unixTime = (long) Math.floor(unixTime / TimeUnit.SECONDS.toMillis(30));
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getValidUnixTimeStamp", unixTime));
    }
    return unixTime;
  }

  /**
   * converts a long to a byteArray. You can choose how big the byteArray shall be, as 
   * well as whether the array shall be in reversed order
   * 
   * @param message the long to convert to a byteArray
   * @param arrayLength the length of the new array
   * @param reversed whether the array shall be reversed
   * @return the byteArray according to specification
   */
  private static byte[] longToByteArray(long message, int arrayLength, boolean reversed) { 
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(message %s, arrayLength %s, reversed %s)", "authenticateToken", message, arrayLength, reversed));
    }
    //define the array
    byte[] data = new byte[arrayLength];
    long value = message;
    if(reversed) {
      for (int i = arrayLength; i-- > 0; value >>>= arrayLength) {
        data[i] = (byte) value;
      }
    } else {
      for (int i = 0; i-- > arrayLength; value >>>= 0) {
        data[i] = (byte) value;
      }
    }
     
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateValidToken", data));
    }
    return data;
  }
  
  /**
   * Some minor sanitation efforts to make the string input more reliable
   * 
   * @param token the token to sanitize
   * @return a sanitizes token
   */
  private static int sanitizeToken(String token) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(token %s)", "sanitizeToken", token));
    }
    int result = 0;
    //the default
    int position = 0;
    token = token.trim();
    int[] sanitizedToken = new int[6];
    for(char c : token.toCharArray()) {
      if(position >= sanitizedToken.length) {
        break;
      }
      int charCode = (int) c;
      int sanitizedChar = 0;
      
      switch(charCode) {
        case 32:  break; //space
        case 33:  sanitizedChar = 49; break; //exclamation mark to 1
        case 66:  sanitizedChar = 56; break; //capital B to 8
        case 71:  sanitizedChar = 54; break; //capital G to 6
        case 73:  sanitizedChar = 49; break; //capital I to 1
        case 79:  sanitizedChar = 48; break; //capital O to 0
        case 98:  sanitizedChar = 56; break; //smaller b to 8      
        case 103: sanitizedChar = 57; break; //smaller g to 9
        case 105: sanitizedChar = 49; break; //smaller i to 1
        case 111: sanitizedChar = 48; break; //smaller o to 0
        
        default: sanitizedChar = charCode; break;
      }
      
      if(sanitizedChar >= 48 && 57 >= sanitizedChar) {
        sanitizedToken[position] = Character.getNumericValue(sanitizedChar);
        
        if (_logger.isTraceEnabled()) {
          _logger.trace("charCode " + charCode + " sanitized: " + sanitizedChar + " at position " + position + ", that's " + Character.getNumericValue(sanitizedChar));
        }
        position++;
      } else {
        if (_logger.isTraceEnabled()) {
          _logger.trace("ignored character: " + sanitizedChar);
        }
      }
    }
    
    for(int i = 0; i < 6; i++) {
      result += sanitizedToken[i];
      if(i<5)
        result *= 10;
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "sanitizeToken", result));
    }
    return result;
  }
  
  /**
   * returns the amount of entries found in the database for a given identityName
   * @param identityName the name of the account to check
   * @return the amount of entries found
   * @throws GeneralException
   * @throws SQLException
   */
  private boolean returnCountForIdentityName(String identityName) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "returnCountForIdentityName", identityName));
    }
    
    boolean result = false;
    int count = 0;
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_COUNT_ACCOUNT_NAME_QUERY);

    prepStatement.setString(1, identityName);

    ResultSet rs = prepStatement.executeQuery();
    if (rs.next()) {
      count = rs.getInt(1);
    }

    rs.close();
    prepStatement.close();
    connection.close();
    
    if(count != 0) {
      result = true;
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "returnCountForIdentityName", result));
    }
    return result;
  }
  
  /**
   * Returns the base32 encoded password of the account
   * @param identityName the name of the account to query for
   * @return the base32 encoded password
   * @throws GeneralException
   * @throws SQLException
   */
  private String returnPasswordFromDB(String identityName) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "returnPasswordFromDB", identityName));
    }
    String result = null;
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_RETRIEVE_PASSWORD_QUERY);

    prepStatement.setString(1, identityName);

    ResultSet rs = prepStatement.executeQuery();
    if (rs.next()) {
      result = rs.getString(1);
    }

    rs.close();
    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "returnSessionIndexFromDb", result));
    }
    return result;
  }
}
