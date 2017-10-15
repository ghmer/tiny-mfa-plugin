package de.whisperedshouts.identityiq.rest;

import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Formatter;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.log4j.Logger;

import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.tools.GeneralException;

@Path("tiny-mfa")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class TinyMfaService extends BasePluginResource {
  private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
	private static final String SQL_RETRIEVE_PASSWORD_QUERY = "SELECT USERPASSWORD FROM MFA_ACCOUNTS WHERE ACCOUNT=?";
	public  static final Logger _logger = Logger.getLogger(TinyMfaService.class);
	
    
	@Override
	public String getPluginName() {
		return "tiny-mfa-plugin";
	}

	@GET
	@Path("validateToken/{identityName}/{token}")
	public Boolean validateToken(@PathParam("identityName") String identityName, @PathParam("token") String token) {
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("ENTERING method %s(identityName %s, token %s)", "authenticateToken", identityName, token));
		}
		
		Boolean isAuthenticated = false;
		try {
		  String userPassword = returnPasswordFromDB(identityName);
		  
    } catch (GeneralException | SQLException e) {
      _logger.error(e.getMessage());
    }
		
		if(_logger.isDebugEnabled()) {
			_logger.debug(String.format("LEAVING method %s (returns: %s)", "authenticateToken", isAuthenticated));
		}
		return isAuthenticated;
	}
	
	/**
	 * This method will calculate corrected timestamps. this is 
         - the timestamp to the full of a half minute
         - half a minute in the past and
         - half a minute in the future.
	 * @return a List containing valid timestamps
	 */
	private List<Long> generateValidTimestamps() {
	  List<Long> timestampList = new ArrayList<>();
	  // Get the current milliseconds since 01.01.1970 00:00:00 GMT
    long unixTime = new Date().getTime() / 1000L;
    /* 
       calculate timestamps
     */    
    long correctedUnixTimestamp = unixTime - (unixTime % 30);
    long pastUnixTimeStamp      = correctedUnixTimestamp - 30L;
    long futureUnixTimestamp    = correctedUnixTimestamp + 30L;
    
    // Add to list and return
    timestampList.add(correctedUnixTimestamp);
    timestampList.add(pastUnixTimeStamp);
    timestampList.add(futureUnixTimestamp);
    
    return timestampList;
	}
	
	private List<String> generateValidTokens(List<Long> correctedTimestamps) {
	  
	  
	  return null;
	}
	
	private String generateValidToken(Long token) {
	  
	  
	  return null;
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

  private static String toHexString(byte[] bytes) {
    Formatter formatter = new Formatter();
    
    for (byte b : bytes) {
      formatter.format("%02x", b);
    }

    return formatter.toString();
  }
  
  private static Long HexToDec(String hexString) {
    long y = Long.parseLong(hexString.trim(), 16);
    return y;
  }

  private static String calculateRFC2104HMAC(String data, String key)
    throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
    Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
    mac.init(signingKey);
    return TinyMfaService.toHexString(mac.doFinal(data.getBytes()));
  }
	
	private String returnPasswordFromDB(String identityName) throws GeneralException, SQLException {
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
}
