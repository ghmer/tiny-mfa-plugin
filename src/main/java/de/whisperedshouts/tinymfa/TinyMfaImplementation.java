/**
 * 
 */
package de.whisperedshouts.tinymfa;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.log4j.Logger;

/**
 * This is an implementation of a time based one time pad (totp)
 * 
 * 
 * @author Mario Enrico Ragucci, mario@whisperedshouts.de
 *
 */
public class TinyMfaImplementation {

  //a logger object. Make use of it!
  private static final Logger _logger = Logger.getLogger(TinyMfaImplementation.class);
   
  // this is the default, static width used in the dynamic truncation
  public static final int DYNAMIC_TRUNCATION_WIDTH = 4;

  // that big is our key to be
  public static final int FINAL_SECRET_SIZE = 16;

  // this is the algorithm that is used to generate the rfc2104hmac hexstring
  public static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
  
  /**
   * Calculates the hmac hash and returns its byteArray representation
   * 
   * @param data
   *          the message to hash (usually a timestamp)
   * @param key
   *          the secretKey to use
   * @return the byteArray representation of the calculated hmac
   * @throws SignatureException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
  private static byte[] calculateRFC2104HMAC(byte[] data, byte[] key)
      throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    if (_logger.isTraceEnabled()) {
      _logger.trace(String.format("ENTERING method %s(data %s, key %s)", "calculateRFC2104HMAC", data, key));
    }
    byte[] result = null;
    SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);
    Mac messageAuthCode      = Mac.getInstance(HMAC_SHA1_ALGORITHM);
    
    messageAuthCode.init(signingKey);
    result = messageAuthCode.doFinal(data);

    if (_logger.isTraceEnabled()) {
      _logger.trace(String.format("LEAVING method %s (returns: %s)", "calculateRFC2104HMAC", result));
    }
    return result;
  }

  /**
   * Generates a new secretKey and encodes it to base32
   * 
   * @return the base32 encoded secretKey
   */
  public static String generateBase32EncodedSecretKey() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "generateBase32EncodedSecretKey"));
    }
    // Allocating the buffer
    byte[] buffer = new byte[128];

    // Filling the buffer with random numbers.
    new Random().nextBytes(buffer);

    // Getting the key and converting it to Base32
    Base32 codec        = new Base32();
    byte[] secretKey    = Arrays.copyOf(buffer, TinyMfaImplementation.FINAL_SECRET_SIZE);
    byte[] bEncodedKey  = codec.encode(secretKey);
    String encodedKey   = new String(bEncodedKey);

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateBase32EncodedSecretKey", encodedKey));
    }
    return encodedKey;
  }

  /**
   * generates a valid token for a timestamp and a base32 encoded secretKey
   * 
   * @param message
   *          the timestamp to use when calculating the token
   * @param base32SecretKey
   *          the base32 encoded secretKey
   * @return the current valid token for this key
   * @throws Exception when we hit an issue
   */
  public static int generateValidToken(Long message, String base32SecretKey) throws Exception {
    if(_logger.isTraceEnabled()) {
      _logger.trace(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken", message, base32SecretKey));
    } else if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(message %s, base32SecretKey %s)", "generateValidToken", message, "***"));
    }
    int token           = 0;
    byte[] keyBytes     = null;
    byte[] messageBytes = null;
    // let's process
    try {
      // the key is base32 encoded
      keyBytes = new Base32().decode(base32SecretKey);
      // get an 8byte array derived from the message
      messageBytes = TinyMfaImplementation.longToByteArray(message);
      // generate the rfc2104hmac String out of timestamp and key
      byte[] rfc2104hmac = TinyMfaImplementation.calculateRFC2104HMAC(messageBytes, keyBytes);

      // get the decimal representation of the last byte
      // this will be used as a offset. i.E if the last byte was 4 (as decimal),
      // we will derive the dynamic trunacted result, starting at the 4th index of the byte array
      int offset = rfc2104hmac[(rfc2104hmac.length - 1)] & 0xF;
      if (_logger.isTraceEnabled()) {
        _logger.trace(String.format("using offset %d for dynamic truncation", (int) offset));
      }
      // probably int is too small (since there is no unsigned integer)
      // therefore, a long variable is used
      long dynamicTruncatedResult = 0;
      for (int i = 0; i < DYNAMIC_TRUNCATION_WIDTH; ++i) {
        // shift 8bit to the left to make room for the next byte
        dynamicTruncatedResult <<= 8;
        // perform a bitwise inclusive OR on the next offset
        // this adds the next digit to the dynamic truncated result
        dynamicTruncatedResult |= (rfc2104hmac[offset + i] & 0xFF);
      }

      // setting the most significant bit to 0
      dynamicTruncatedResult &= 0x7FFFFFFF;
      // making sure we get the right amount of numbers
      dynamicTruncatedResult %= 1000000;

      token = (int) dynamicTruncatedResult;

    } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
      _logger.error(e.getMessage(), e);
      throw new Exception(e.getMessage());
    }

    if(_logger.isTraceEnabled()) {
      _logger.trace(String.format("LEAVING method %s (returns: %s)", "generateValidToken", token));
    } else if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateValidToken", "***"));
    }
    return token;
  }

  /**
   * returns a message based on a "corrected timestamp" This method will get the
   * current system time (Milliseconds since 1970), then remove the seconds
   * elapsed since the last half minute (i.E. 34 becomes 30). Last, we divide this by
   * 30.
   * 
   * @return the message
   */
  public static long getValidMessageBySystemTimestamp() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "getValidMessageBySystemTimestamp"));
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
   * converts a long to a byteArray.
   * 
   * @param message
   *          the long to convert to a byteArray
   * @return the byteArray according to specification
   */
  private static byte[] longToByteArray(long message) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(message %s)", "longToByteArray", message));
    }

    // define the array
    byte[] data = new byte[8];
    long value  = message;

    for (int i = 8; i-- > 0; value >>>= 8) {
      data[i]  = (byte) value;
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "longToByteArray", data));
    }
    return data;
  }
}
