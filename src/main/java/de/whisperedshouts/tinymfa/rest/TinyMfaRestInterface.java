package de.whisperedshouts.tinymfa.rest;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;

import de.whisperedshouts.tinymfa.TinyMfaImplementation;
import de.whisperedshouts.tinymfa.util.TinyMfaUtil;
import sailpoint.api.SailPointContext;
import sailpoint.object.Capability;
import sailpoint.object.Identity;
import sailpoint.plugin.PluginBaseHelper;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.rest.plugin.RequiredRight;
import sailpoint.tools.GeneralException;

/**
 * This is a rest service used by the IdentityIQ TinyMFA plugin. Its purpose is
 * - To generate totp tokens for an identity 
 * - To supply the identity with a proper otpauth url (to be used in QRCodes) 
 * - To serve as a backend to verify tokens
 * 
 * @author Mario Enrico Ragucci <mario@whisperedshouts.de>
 *
 */
@Path("tiny-mfa")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class TinyMfaRestInterface extends BasePluginResource {
  // a logger object. Make use of it!
  private static final Logger _logger = Logger.getLogger(TinyMfaRestInterface.class);

  //the capability to assign once a user shall be mfa activated
   public static final String CAPABILITY_ACTIVATED_IDENTITY_NAME = "TinyMFAActivatedIdentity";
   
  //the administrative SPRight name
  public static final String SPRIGHT_ADMINISTRATOR_NAME = "TinyMfaPluginAdministrator";

  // a format string for the qr code
  public static final String QR_CODE_FORMATSTRING = "otpauth://totp/%1$s:%2$s@%1$s?algorithm=SHA1&digits=6&issuer=%1$s&period=30&secret=%3$s";

  // check for failed validation attempts
  public static final String SQL_COUNT_VALIDATION_ATTEMPTS = "SELECT COUNT(*) FROM MFA_VALIDATION_ATTEMPTS WHERE CTS = ? and ACCOUNT_NAME = ? and SUCCEEDED = ?";

  // insert a new account into the database. This happens on first usage of the
  // plugin
  public static final String SQL_CREATE_NEW_ACCOUNT_QUERY = "INSERT INTO MFA_ACCOUNTS(ACCOUNT_NAME, USERPASSWORD, ISENCRYPTED, ISDISABLED) VALUES(?,?,?,?)";

  // insert a new validation attempt into the database
  public static final String SQL_INSERT_VALIDATION_ATTEMPT = "INSERT INTO MFA_VALIDATION_ATTEMPTS(ACCESS_TIME,CTS,ACCOUNT_NAME,ACCOUNT_STATUS,SUCCEEDED) VALUES(?,?,?,?,?)";

  // check if user is disabled
  public static final String SQL_IS_ACCOUNT_DISABLED = "SELECT ISDISABLED FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";

  // the SQL query used to retrieve the userkey from the database
  public static final String SQL_RETRIEVE_PASSWORD_QUERY = "SELECT USERPASSWORD FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";

  // select specific account attributes
  public static final String SQL_SELECT_ACCOUNT = "SELECT ID, ACCOUNT_NAME, ISENCRYPTED, ISDISABLED FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";

  // select all account attributes
  public static final String SQL_SELECT_ALL_ACCOUNTS = "SELECT ID, ACCOUNT_NAME, ISENCRYPTED, ISDISABLED FROM MFA_ACCOUNTS";

  // select audit trail
  public static final String SQL_SELECT_AUDIT = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_STATUS, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC";

  /**
   * activates a token for an identity
   * 
   * @param identityName
   *          the name of the account to activate
   * @param token
   *          the token to use
   * @return true whether the token could be validated
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("token/activate/{identityName}/{token}")
  public Boolean activateToken(@PathParam("identityName") String identityName, @PathParam("token") String token) {
    if (_logger.isDebugEnabled()) {
      _logger
          .debug(String.format("ENTERING method %s(identityName %s, token %s)", "activateToken", identityName, token));
    }

    SailPointContext context = getContext();
    
    // that's what we care for
    Boolean isAuthenticated = validateToken(identityName, token, context);
    Identity identity       = null;
    Capability capability   = null;

    if (isAuthenticated) {
      try {
        identity = context.getObjectByName(Identity.class, identityName);
      } catch (GeneralException e) {
        _logger.error("Could not activate identity " + identityName + ": " + e.getMessage());
        isAuthenticated = false;
      }
    }

    if (identity != null) {
      try {
        capability = context.getObjectByName(Capability.class, CAPABILITY_ACTIVATED_IDENTITY_NAME);
      } catch (GeneralException e) {
        _logger.error("Could not get capability " + CAPABILITY_ACTIVATED_IDENTITY_NAME + ": " + e.getMessage());
        isAuthenticated = false;
      }
    }

    if (identity != null && capability != null) {
      try {
        identity.add(capability);
        context.saveObject(identity);
        context.commitTransaction();
      } catch (GeneralException e) {
        _logger.error(
            "Could assign capability " + CAPABILITY_ACTIVATED_IDENTITY_NAME + " to identity " + identityName + ": " + e.getMessage());
        isAuthenticated = false;
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "activateToken", isAuthenticated));
    }
    return isAuthenticated;
  }

  /**
   * returns the requested account details
   * 
   * @param identityName
   *          the identity to query for
   * @return a list of all matching accounts
   */
  @GET
  @RequiredRight(value = "TinyMfaPluginAdministrator")
  @Produces(MediaType.APPLICATION_JSON)
  @Path("accounts/{identityName}")
  public Response getAccount(@PathParam("identityName") String identityName) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "getAccount", identityName));
    }

    List<Map<String, Object>> result = new ArrayList<>();
    Connection connection            = null;
    PreparedStatement prepStatement  = null;
    try {
      connection    = getConnection();
      prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_SELECT_ACCOUNT);
      prepStatement.setString(1, identityName);

      ResultSet resultSet = prepStatement.executeQuery();
      while (resultSet.next()) {
        Map<String, Object> accountObject = TinyMfaUtil.buildAccountObjectMap(resultSet);
        result.add(accountObject);
      }

      resultSet.close();
      prepStatement.close();
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    } finally {
      if (connection != null) {
        try {
          connection.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getAccount", result));
    }

    return Response.ok().entity(result).build();
  }

  /**
   * returns accounts from the database
   * 
   * @return a list of accounts
   */
  @GET
  @RequiredRight(value = "TinyMfaPluginAdministrator")
  @Produces(MediaType.APPLICATION_JSON)
  @Path("accounts")
  public Response getAccounts() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "getAccounts"));
    }

    List<Map<String, Object>> result = new ArrayList<>();
    Connection connection = null;
    PreparedStatement prepStatement;
    try {
      connection = getConnection();
      prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_SELECT_ALL_ACCOUNTS);

      ResultSet resultSet = prepStatement.executeQuery();
      while (resultSet.next()) {
        Map<String, Object> accountObject = TinyMfaUtil.buildAccountObjectMap(resultSet);
        result.add(accountObject);
      }

      resultSet.close();
      prepStatement.close();
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    } finally {
      if (connection != null) {
        try {
          connection.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getAccounts", result));
    }

    return Response.ok().entity(result).build();
  }

  /**
   * returns the links for the appstore entries
   * 
   * @return a Map containing links for ios and android
   */
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("getAppstoreLinks")
  public Response getAppstoreLinks() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "getAppstoreLinks"));
    }

    String iosAppstoreLink      = PluginBaseHelper.getSettingString(getPluginName(), "mfaAppIos");
    String androidAppstoreLink  = PluginBaseHelper.getSettingString(getPluginName(), "mfaAppAndroid");
    Map<String, String> result  = new HashMap<>();

    result.put("iosAppstoreLink", iosAppstoreLink);
    result.put("androidAppstoreLink", androidAppstoreLink);

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getAppstoreLinks", result));
    }

    return Response.ok().entity(result).build();
  }

  /**
   * returns the validation attempts
   * 
   * @return a list containing the validation attempts
   */
  @GET
  @RequiredRight(value = "TinyMfaPluginAdministrator")
  @Produces(MediaType.APPLICATION_JSON)
  @Path("audit")
  public Response getAudit() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "getAudit"));
    }

    List<Map<String, Object>> result  = new ArrayList<>();
    Connection connection             = null;
    PreparedStatement prepStatement   = null;
    try {
      connection = getConnection();
      prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_SELECT_AUDIT);
      ResultSet resultSet = prepStatement.executeQuery();
      while (resultSet.next()) {
        Map<String, Object> auditObject = TinyMfaUtil.buildAuditObjectMap(resultSet);
        result.add(auditObject);
      }

      resultSet.close();
      prepStatement.close();
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    } finally {
      if (connection != null) {
        try {
          connection.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getAudit", result));
    }

    return Response.ok().entity(result).build();
  }
  
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("accounts/isAdmin")
  public Response isAdmin() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "isAdmin"));
    }

    boolean result = false;
    try {
      String username = getLoggedInUserName();
      Collection<String> userRights = getLoggedInUserRights();
      _logger.trace(userRights);
      for(String userRight : userRights) {
        _logger.trace("userRight: " + userRight);
        if(userRight.equalsIgnoreCase(TinyMfaRestInterface.SPRIGHT_ADMINISTRATOR_NAME)) {
          result = true;
          break;
        }
      }
      
      if(username.equalsIgnoreCase("spadmin")) {
        result = true;
      }
      
    }catch(Exception e) {
      _logger.error(e.getMessage());
    }
    
    

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "isAdmin", result));
    }

    return Response.ok().entity(result).build();
  }

  /**
   * returns the validation attempts, limits the result to the supplied number
   * 
   * @param limit
   *          the limit of validation attempts to show
   * @return a list containing the validation attempts
   */
  @GET
  @RequiredRight(value = "TinyMfaPluginAdministrator")
  @Produces(MediaType.APPLICATION_JSON)
  @Path("audit/{limit}")
  public Response getAuditWithLimit(@PathParam("limit") int limit) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(limit %s)", "getAuditWithLimit", limit));
    }

    int count = 0;
    List<Map<String, Object>> result  = new ArrayList<>();
    Connection connection             = null;
    PreparedStatement prepStatement   = null;
    try {
      connection = getConnection();
      prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_SELECT_AUDIT);
      ResultSet resultSet = prepStatement.executeQuery();
      while (resultSet.next() && count < limit) {
        Map<String, Object> auditObject = TinyMfaUtil.buildAuditObjectMap(resultSet);
        result.add(auditObject);
        count++;
      }

      resultSet.close();
      prepStatement.close();
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    } finally {
      if (connection != null) {
        try {
          connection.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getAuditWithLimit", result));
    }

    return Response.ok().entity(result).build();
  }

  @Override
  public String getPluginName() {
    return "tiny_mfa_plugin";
  }

  /**
   * generates the appropriate totp url that is transferred within the QRCode.
   * This can be used with google authenticator. If the account cannot be found
   * in the database, it will be created
   * 
   * @return the application-url to send with the QRCode
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("token/qrcode")
  public Response getQrCodeData() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "getQrCodeData"));
    }
    boolean hasError      = false;
    String qrCodeUrl      = null;
    String identityName   = null;
    String sanitizedName  = null;
    String issuer         = PluginBaseHelper.getSettingString(getPluginName(), "issuerDomain");
    try {
      identityName = getLoggedInUserName();
      // sanitize the identityName;
      sanitizedName = java.net.URLEncoder.encode(identityName, "UTF-8");
      sanitizedName = sanitizedName.replaceAll(" ", "%20");
    } catch (Exception e) {
      _logger.error(e.getMessage());
      hasError = true;
    }

    // no errors so far, continue with qrCodeUrl formatting
    if (!hasError) {
      String userPassword       = null;
      SailPointContext context  = null;
      try {
        context      = getContext();
        userPassword = returnPasswordFromDb(identityName, context);
        if (userPassword == null || userPassword.isEmpty()) {
          userPassword = createAccount(identityName, context);
        }

        // trim the password - IOS orders us to do so!
        userPassword = userPassword.substring(0, userPassword.indexOf("="));
        qrCodeUrl    = String.format(QR_CODE_FORMATSTRING, issuer, sanitizedName, userPassword);

      } catch (Exception e) {
        _logger.error(e.getMessage());
        hasError = true;
      }

    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getQrCodeData", qrCodeUrl));
    }
    // return either an error or the qrCodeUrl
    return (hasError) ? Response.serverError().build() : Response.ok().entity(qrCodeUrl).build();
  }

  /**
   * validates a token for an identity
   * 
   * @param identityName
   *          the name of the account to check the token for
   * @param token
   *          the token to check
   * @return true whether the token could be validated
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @Path("token/validate/{identityName}/{token}")
  public Boolean validateToken(@PathParam("identityName") String identityName, @PathParam("token") String token) {
    if (_logger.isDebugEnabled()) {
      _logger
          .debug(String.format("ENTERING method %s(identityName %s, token %s)", "validateToken", identityName, token));
    }

    SailPointContext context = getContext();

    // that's what we care for
    Boolean isAuthenticated = false;
    isAuthenticated         = validateToken(identityName, token, context);

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "validateToken", isAuthenticated));
    }
    return isAuthenticated;
  }

  /**
   * validates a token for an identity. This method is not exposed via REST.
   * Instead, it needs an existing SailPointContext to work This method is used
   * via reflection in the MFA workflow
   * 
   * @param identityName
   *          the name of the account to check the token for
   * @param token
   *          the token to check
   * @param context
   *          a SailPointContext to use
   * @return true whether the token could be validated
   */
  public Boolean validateToken(String identityName, String token, SailPointContext context) {
    if (_logger.isDebugEnabled()) {
      _logger
          .debug(String.format("ENTERING method %s(identityName %s, token %s, context %s)", "validateToken", identityName, token, context));
    }

    // that's what we care for
    Boolean isAuthenticated = false;
    Boolean isDisabled      = true;
    
    // check whether the account is disabled
    try {
      isDisabled = isAccountDisabled(identityName, context);
    } catch (GeneralException | SQLException e) {
      _logger.error(e.getMessage());
    }

    // only proceed if the account is not disabled
    if (!isDisabled) {
      // get the maximum attempts from the plugin settings
      int maximumAllowedValidationAttempts = PluginBaseHelper.getSettingInt(getPluginName(), "maxAttempts");

      // get the current timestamp to generate the token
      long currentUnixTime = TinyMfaImplementation.getValidMessageBySystemTimestamp();

      // check for validation attempts, initialize with safety in mind
      int attemptsForTimestamp = maximumAllowedValidationAttempts + 1;
      try {
        attemptsForTimestamp = returnFailedValidationAttempts(identityName, currentUnixTime);
      } catch (GeneralException e1) {
        _logger.error(e1.getMessage());
      } catch (SQLException e1) {
        _logger.error(e1.getMessage());
      }

      if (attemptsForTimestamp < maximumAllowedValidationAttempts) {
        int generatedToken = 0;
        // sanitize the token (just to be sure)
        int sanitizedToken = TinyMfaUtil.sanitizeToken(token, 6);

        try {
          if (context == null) {
            context = getContext();
          }
          String userPassword = returnPasswordFromDb(identityName, context);
          generatedToken      = TinyMfaImplementation.generateValidToken(currentUnixTime, userPassword);

          // if codes match, you are welcome
          isAuthenticated     = (generatedToken == sanitizedToken);

          // log the attempt
          insertValidationAttemptToDb(identityName, currentUnixTime, isDisabled, isAuthenticated);
        } catch (GeneralException | SQLException e) {
          _logger.error(e.getMessage());
        }
      } else {
        _logger.warn(String.format("number attempts (%s) exceeded limit %s for identity %s", attemptsForTimestamp,
            maximumAllowedValidationAttempts, identityName));
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "validateToken", isAuthenticated));
    }
    return isAuthenticated;
  }

  /**
   * Creates an account on the database
   * 
   * @param identityName
   *          the account to create
   * @param context
   *          a SailPointContext to use
   * @return the base32 encoded secretKey of the created account
   * @throws GeneralException
   * @throws SQLException
   */
  private String createAccount(String identityName, SailPointContext context) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "createAccount", identityName));
    }

    // generate a new secret key. User must not be bothered with this
    String generatedPassword = null;
    String encryptedPassword = null;

    generatedPassword = TinyMfaImplementation.generateBase32EncodedSecretKey();
    encryptedPassword = context.encrypt(generatedPassword);
  

    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_CREATE_NEW_ACCOUNT_QUERY);

    prepStatement.setString(1, identityName);
    prepStatement.setString(2, encryptedPassword);
    prepStatement.setString(3, "true");  
    prepStatement.setString(4, "false");

    int resultCode = prepStatement.executeUpdate();
    if (resultCode != 0) {
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
   * Inserts a validation attempt to the database
   * 
   * @param identityName
   *          the name of the account to query for
   * @param cts
   *          the corrected timestamp to query for
   * @return
   * @throws GeneralException
   * @throws SQLException
   */
  private boolean insertValidationAttemptToDb(String identityName, long cts, boolean isDisabled, boolean succeeded)
      throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s, cts %s, succeeded %s)",
          "insertValidationAttemptToDb", identityName, cts, succeeded));
    }

    boolean wasCompleted = false;

    Connection connection           = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_INSERT_VALIDATION_ATTEMPT);
    
    prepStatement.setDate(1, new java.sql.Date(new java.util.Date().getTime()));
    prepStatement.setLong(2, cts);
    prepStatement.setString(3, identityName);
    prepStatement.setString(4, (isDisabled) ? "active" : "inactive");
    prepStatement.setBoolean(5, succeeded);

    int resultCode = prepStatement.executeUpdate();
    if (resultCode != 0) {
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
   * checks if a given account is disabled
   * 
   * @param identityName
   *          the identityName to check
   * @param context
   *          a SailPointContext to use
   * @return true if the account is disabled
   * @throws GeneralException
   * @throws SQLException
   */
  private Boolean isAccountDisabled(String identityName, SailPointContext context)
      throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(identityName %s, context %s)", "isAccountDisabled", identityName, context));
    }
    boolean isDisabled              = true;
    Connection connection           = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_IS_ACCOUNT_DISABLED);

    prepStatement.setString(1, identityName);

    ResultSet resultSet = prepStatement.executeQuery();
    if (resultSet.next()) {
      isDisabled = resultSet.getBoolean(1);
    }

    resultSet.close();
    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "isAccountDisabled", isDisabled));
    }

    return isDisabled;
  }

  /**
   * Returns the number of failed validation attempts that have been made for
   * the given identityName and corrected timestamp
   * 
   * @param identityName
   *          the name of the account to query for
   * @param cts
   *          the corrected timestamp to query for
   * @return the number of validation attempts for this identityName and cts
   * @throws GeneralException
   * @throws SQLException
   */
  private int returnFailedValidationAttempts(String identityName, long cts) throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s, cts %s)", "returnFailedValidationAttempts",
          identityName, cts));
    }
    int result            = 0;
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_COUNT_VALIDATION_ATTEMPTS);

    prepStatement.setString(1, identityName);
    prepStatement.setLong(2, cts);
    prepStatement.setBoolean(3, false);

    ResultSet resultSet = prepStatement.executeQuery();
    if (resultSet.next()) {
      result = resultSet.getInt(1);
    }

    resultSet.close();
    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "returnFailedValidationAttempts", result));
    }
    return result;
  }

  /**
   * returns the password for the given identityName
   * 
   * @param identityName
   *          the name of the identity
   * @param context
   *          a SailPointContext to use
   * @return the password of the identity
   * @throws GeneralException
   * @throws SQLException
   */
  private String returnPasswordFromDb(String identityName, SailPointContext context)
      throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s, context %s)", "returnPasswordFromDb",
          identityName, context));
    }
    String result         = null;
    Connection connection = getConnection();
    PreparedStatement prepStatement = connection.prepareStatement(TinyMfaRestInterface.SQL_RETRIEVE_PASSWORD_QUERY);

    prepStatement.setString(1, identityName);

    ResultSet resultSet = prepStatement.executeQuery();
    if (resultSet.next()) {
      String encryptedPassword = resultSet.getString(1);
      result = context.decrypt(encryptedPassword);
    }

    resultSet.close();
    prepStatement.close();
    connection.close();

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "returnPasswordFromDb", result));
    }
    return result;
  }
}