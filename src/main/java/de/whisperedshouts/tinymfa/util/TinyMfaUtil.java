/**
 * 
 */
package de.whisperedshouts.tinymfa.util;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;

import org.apache.log4j.Logger;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;


/**
 * @author Mario Enrico Ragucci, mario@whisperedshouts.de
 *
 */
public class TinyMfaUtil {

  //a logger object. Make use of it!
  private static final Logger _logger     = Logger.getLogger(TinyMfaUtil.class);
  public static final String DATE_FORMAT  = "yyyy-MM-dd HH:mm:ss z";
 
  /**
   * builds a Map containing account information from a resultSet
   * @param resultSet the resultset to get the information form
   * @return the Map containing the account information
   * @throws SQLException when there was an error with the result set
   */
  public static Map<String, Object> buildAccountObjectMap(ResultSet resultSet) throws SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(resultSet %s)", "buildAccountObjectMap", resultSet));
    }
    String id           = resultSet.getString(1);
    String accountName  = resultSet.getString(2);
    boolean isDisabled  = resultSet.getBoolean(3);

    Map<String, Object> accountObject = new HashMap<>();
    accountObject.put("id", id);
    accountObject.put("account", accountName);
    accountObject.put("disabled", isDisabled);
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "buildAccountObjectMap", accountObject));
    }    
    return accountObject;
  }
  
  /**
   * builds a Map with audit information
   * 
   * @param resultSet
   *          the resultset to get the information from
   * @return Map containing the audit information
   * @throws SQLException
   *           when we hit an issue with the result set
   */
  public static Map<String, Object> buildAuditObjectMap(ResultSet resultSet) throws SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(resultSet %s)", "buildAuditObjectMap", resultSet));
    }
    String id           = resultSet.getString(1);
    long accessTime     = resultSet.getLong(2);
    String cts          = resultSet.getString(3);
    String accountName  = resultSet.getString(4);
    String status       = resultSet.getString(5);
    boolean succeeded   = resultSet.getBoolean(6);

    Map<String, Object> auditObject = new HashMap<>();
    auditObject.put("id", id);
    auditObject.put("account", accountName);
    auditObject.put("status", status);
    auditObject.put("accessTime", formatAccessTime(accessTime));
    auditObject.put("cts", cts);
    auditObject.put("succeeded", succeeded);
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "buildAuditObjectMap", auditObject));
    }
    return auditObject;
  }
  
  /**
   * formats the accesstime to a String object
   * @param accessTime the long representing the date
   * @return a formatted String
   */
  private static Object formatAccessTime(long accessTime) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(accessTime %s)", "formatAccessTime", accessTime));
    }
    String result         = String.valueOf(accessTime);
    try {
      SimpleDateFormat sdf  = new SimpleDateFormat(TinyMfaUtil.DATE_FORMAT);
      Date accessTimeDate   = new Date(accessTime);
      
      result = sdf.format(accessTimeDate);
    } catch(Exception e) {
      _logger.error(e.getMessage());
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "formatAccessTime", result));
    }
    return result;
  }
  
  /**
   * Generates a QRCode image in PNG format with the supplied payload, then
   * encodes it to base64
   * 
   * @param qrCodePayload
   *          the payload that the QRCode shall carry
   * @return the base64 encoded QRCode image.png
   */
  public static String generateBase64EncodedQrcode(String qrCodePayload) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(qrCodePayload %s)", "generateBase64EncodedQrcode", qrCodePayload));
    }
    String qrCode   = null;
    int width       = 300;
    int height      = 300;
    String fileType = "png";
    
    try {
      Map<EncodeHintType, Object> hintMap = new EnumMap<EncodeHintType, Object>(EncodeHintType.class);
      hintMap.put(EncodeHintType.CHARACTER_SET, "UTF-8");
      
      // Now with zxing version 3.2.1 you could change border size (white border size to just 1)
      hintMap.put(EncodeHintType.MARGIN, 1); // default = 4
      hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);

      QRCodeWriter qrCodeWriter = new QRCodeWriter();
      BitMatrix byteMatrix = qrCodeWriter.encode(qrCodePayload, BarcodeFormat.QR_CODE, width,
          height, hintMap);
      
      BufferedImage image = generateQrcodeGraphics(width, height, byteMatrix);
      
      qrCode = encodeImageToBase64String(fileType, image);
      

    } catch (IOException e) {
      _logger.error(e.getMessage());
    } catch (WriterException e) {
      _logger.error(e.getMessage());
    }
    
    if (_logger.isDebugEnabled()) {
      if(_logger.isTraceEnabled()) {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateBase64EncodedQrcode", qrCode));
      } else {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateBase64EncodedQrcode", "*** (masked)"));
      }
    } 
    return qrCode;
  }

  /**
   * encodes a BufferedImage to base64
   * 
   * @param fileType
   *          type to use when writing the image (i.E. png)
   * @param image
   *          the BufferedImage to encode
   * @throws IOException
   *           when there was an issue while converting the Image
   * @return the base64 encoded representation of the image
   * @throws IOException
   */
  public static String encodeImageToBase64String(String fileType, BufferedImage image) throws IOException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(fileType %s, image %s)", "encodeImageToBase64String", fileType, image));
    }
    String result  = null;
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    OutputStream base64OutputStream = Base64.getEncoder().wrap(os);
    ImageIO.write(image, fileType, base64OutputStream);
 
    base64OutputStream.close();
    result = os.toString();
    os.close();
    
    if (_logger.isDebugEnabled()) {
      if(_logger.isTraceEnabled()) {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "encodeImageToBase64String", result));
      } else {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "encodeImageToBase64String", "*** (masked)"));
      }
    }
    return result;
  }

  /**
   * generates a QRCode image with the supplied width, height and Bitmatrix
   * 
   * @param width
   *          the width of the QRCode
   * @param height
   *          the height of the QRCode
   * @param bitMatrix
   *          the bitMatrix representing the QRCode's payload
   * @return
   */
  public static BufferedImage generateQrcodeGraphics(int width, int height, BitMatrix bitMatrix) {
    if (_logger.isDebugEnabled()) {
      if(_logger.isTraceEnabled()) {
        _logger.debug(String.format("ENTERING method %s(width %s, height %s, bitMatrix %s)", "generateQrcodeGraphics", width, height, bitMatrix));
      } else {
        _logger.debug(String.format("ENTERING method %s(width %s, height %s, bitMatrix %s)", "generateQrcodeGraphics", width, height, "*** (masked)"));
      }
    }
    
    BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
    image.createGraphics();

    Graphics2D graphics = (Graphics2D) image.getGraphics();
    graphics.setColor(Color.WHITE);
    graphics.fillRect(0, 0, width, height);
    graphics.setColor(Color.BLACK);

    for (int xPosition = 0; xPosition < width; xPosition++) {
      for (int yPosition = 0; yPosition < height; yPosition++) {
        if (bitMatrix.get(xPosition, yPosition)) {
          graphics.fillRect(xPosition, yPosition, 1, 1);
        }
      }
    }
    
    if (_logger.isDebugEnabled()) {
      if(_logger.isTraceEnabled()) {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateQrcodeGraphics", image));
      } else {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "generateQrcodeGraphics", "*** (masked)"));
      }
    }
    return image;
  }

  /**
   * Some minor sanitation efforts to make the string input more reliable
   * 
   * @param token
   *          the token to sanitize
   * @param desiredLength
   *          the desired length of the sanitized string
   * @return a sanitizes token
   */
  public static int sanitizeToken(String token, int desiredLength) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(token %s, desiredLength %s)", "sanitizeToken", token, desiredLength));
    }

    // return variable
    int result   = 0;
    // current position result variable
    int position = 0;

    // iterate over string characters
    for (int i = 0; i < token.length(); i++) {
      if (position >= desiredLength) {
        break;
      }
      // cast to byte
      byte b = (byte) token.charAt(i);
      switch (b) {
        case 32: break;         // space
        case 33: b = 49; break; // exclamation mark to 1
        case 66: b = 56; break; // capital B to 8
        case 71: b = 54; break; // capital G to 6
        case 73: b = 49; break; // capital I to 1
        case 79: b = 48; break; // capital O to 0
        case 98: b = 56; break; // smaller b to 8
        case 103:b = 57; break; // smaller g to 9
        case 105:b = 49; break; // smaller i to 1
        case 111:b = 48; break; // smaller o to 0
      }

      // check if character is in allowed range
      if (b >= 48 && 57 >= b) {
        // add decimal representation of the character to the result variable
        result += b & 0xF;
        // raise position
        position++;
        // as long as we have not met the desired length, shift value to left
        if (position != desiredLength) {
          result *= 10;
        }
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "sanitizeToken", result));
    }
    return result;
  }
}
