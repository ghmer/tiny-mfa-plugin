package de.whisperedshouts.identityiq.rest;

import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Formatter;
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

import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.tools.GeneralException;

@Path("tiny-mfa")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class TinyMfaService extends BasePluginResource {
  //this is the algorithm that is used to generate the rfc2104hmac hexstring
  public static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
  //this is the default, static width used in the dynamic truncation
  public static final int DYNAMIC_TRUNCATION_WIDTH = 4;
  
  final String s = "otpauth://totp/%s:%s@%s?algorithm=SHA1&digits=6&issuer=%s&period=30&secret=%s";
	public static final String SQL_RETRIEVE_PASSWORD_QUERY = "SELECT USERPASSWORD FROM MFA_ACCOUNTS WHERE ACCOUNT=?";
	public  static final Logger _logger = Logger.getLogger(TinyMfaService.class);
	
    
	@Override
	public String getPluginName() {
		return "tiny-mfa-plugin";
	}
	
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	@Path("demoQrCodeData")
	public Response getDemoQrCodeData() {
	  String issuer = "sailpoint.labs";
	  String identityName = "bob";
	  String secret = "K3XT7VEUS7JFJVCX";
	  
	  return Response.ok().entity(String.format(s, issuer, identityName, issuer, issuer, secret)).build();
	}
	@GET
	@Path("validateToken/{identityName}/{token}")
	public Boolean validateToken(@PathParam("identityName") String identityName, @PathParam("token") String token) {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s(identityName %s, token %s)", "authenticateToken", identityName, token));
		}
		
		Boolean isAuthenticated = false;
		try {
		  //TODO: String userPassword = 
		  returnPasswordFromDB(identityName);
		  
    } catch (GeneralException | SQLException e) {
      _logger.error(e.getMessage());
    }
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "authenticateToken", isAuthenticated));
		}
		return isAuthenticated;
	}
	
	public static String generateValidToken(Long timestamp, String key) throws GeneralException {
	  String token     = null;
	  byte[] keyBytes  = new Base32().decode(key);
	  // let's process
	  try {
	    //generate the rfc2104hmac String out of timestamp and key
      String rfc2104hmac   = TinyMfaService.calculateRFC2104HMAC(timestamp, keyBytes);
      
      //get the integer value of the last 4 bytes of the rfc2103 hex string (the last character)
      //this is our base for our dynamic truncation
      int dynamicTruncationStart = Integer.parseInt(rfc2104hmac.substring(rfc2104hmac.length() - 1), 16);
      
      //split the hmac hex string into an array of 8 bytes (2 characters each)
      String[] eightBytesArray = splitTo8BytesArray(rfc2104hmac);
      
      //dynamically truncate the string
      String dynamicTruncatedString = dynamicTruncate(eightBytesArray, 
          dynamicTruncationStart, 
          TinyMfaService.DYNAMIC_TRUNCATION_WIDTH);
      
      //get our token, pad it properly with trailing zeroes
      token = String.format("%06d",
          generatePaddedToken(hexStringToDecimal(dynamicTruncatedString)));
    } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
      _logger.error(e.getMessage(),e);
      throw new GeneralException(e.getMessage());
    }
	  return token;
	}
	
	public static String[] splitTo8BytesArray(String data) {
    String[] array = new String[20];
    char tempChar = 0;
    int positionInArray = 0;
    for(int positionInString = 0; positionInString < data.length(); positionInString++) {
      if(positionInString % 2 == 0) {
        tempChar = data.charAt(positionInString);
      }else {
        String eightBytes = String.valueOf(tempChar) + String.valueOf(data.charAt(positionInString));
        array[positionInArray] = eightBytes;
        positionInArray++;
      }
    }
    
    return array;
  }
	
	public static String dynamicTruncate(String[] array, int start, int width) {
    StringWriter stringWriter = new StringWriter();
    for(int i = start; i < start + width; i++) {
      stringWriter.write(array[i]);
    }
    
    return stringWriter.toString();
  }

  public static String toHexString(byte[] bytes) {
    Formatter formatter = new Formatter();
    
    for (byte b : bytes) {
      formatter.format("%02x", b);
    }

    String result = formatter.toString();
    if(formatter != null) {
      formatter.close();
    }
    return result;
  }
  
  public static Long hexStringToDecimal(String hexString) {
    long y = Long.parseLong(hexString.trim(), 16);
    return y;
  }
  
  public static Long generatePaddedToken(Long truncatedString) {
    return truncatedString % 1000000;
  }

  public static String calculateRFC2104HMAC(long timestamp, byte[] key)
    throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
    Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
    mac.init(signingKey);
    
    byte[] data = new byte[8];
    long value = timestamp;
    for (int i = 8; i-- > 0; value >>>= 8) {
      data[i] = (byte) value;
    }
    return TinyMfaService.toHexString(mac.doFinal(data));
  }
	
	public String returnPasswordFromDB(String identityName) throws GeneralException, SQLException {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s(identityName %s)", "returnPasswordFromDB", identityName));
		}
		String result = null;
		Connection connection = getConnection();
		PreparedStatement prepStatement = connection.prepareStatement(TinyMfaService.SQL_RETRIEVE_PASSWORD_QUERY);
		
		prepStatement.setString(1, identityName);
		
		ResultSet rs = prepStatement.executeQuery();
		if(rs.next()) {
			result = rs.getString(1);
		}
		
		rs.close();
		prepStatement.close();
		connection.close();
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "returnSessionIndexFromDb", result));
		}
		return result;
	}
	
	public static void main(String[] args) throws GeneralException {
	  long unixTime = System.currentTimeMillis() / TimeUnit.SECONDS.toMillis(30);
    System.out.println(unixTime);  
    System.out.println(TinyMfaService.generateValidToken(unixTime, "XPPHTHD2QTADIBXJ"));
    
	}
}
