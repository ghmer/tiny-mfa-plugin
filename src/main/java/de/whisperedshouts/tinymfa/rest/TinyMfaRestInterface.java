package de.whisperedshouts.tinymfa.rest;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
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
import de.whisperedshouts.tinymfa.util.SqlSelectHelper;
import de.whisperedshouts.tinymfa.util.SqlSelectHelper.QUERY_TYPE;
import de.whisperedshouts.tinymfa.util.TinyMfaUtil;
import sailpoint.api.SailPointContext;
import sailpoint.object.Capability;
import sailpoint.object.Identity;
import sailpoint.object.Request;
import sailpoint.object.RequestDefinition;
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
 * @author Mario Enrico Ragucci, mario@whisperedshouts.de
 *
 */
@Path("tiny-mfa")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.TEXT_PLAIN)
@AllowAll
public class TinyMfaRestInterface extends BasePluginResource {
  /**
   * a logger object. Make use of it!
   */
  private static final Logger _logger = Logger.getLogger(TinyMfaRestInterface.class);

  /**
   * the capability to assign once a user shall be mfa activated
   */
  private static final String CAPABILITY_ACTIVATED_IDENTITY_NAME = "TinyMFAActivatedIdentity";
 
  /**
   * the capability that gives basic access to the plugin page
   */
  private static final String CAPABILITY_PLUGIN_ACCESS = "TinyMFAPluginAccess";
  
  /**
   * the capability that is given to plugin administrators
   */
  private static final String CAPABILITY_PLUGIN_ADMIN  = "TinyMFAAdministrator";
  
  /**
   * a format string for the qr code
   */
  private static final String QR_CODE_FORMATSTRING = "otpauth://totp/%1$s:%2$s@%1$s?algorithm=SHA1&digits=6&issuer=%1$s&period=30&secret=%3$s";

  /**
   * the administrative SPRight name
   */
  private static final String SPRIGHT_ADMINISTRATOR_NAME = "TinyMfaPluginAdministrator";

  /**
   * the workflow being used to provision the capabilities
   */
  private static final String TINY_MFA_ENROLL_USER_WORKFLOW = "TinyMFA Enroll User Workflow";

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
    Boolean isAuthenticated = isValidToken(identityName, token, context);
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
   * modifies the account status (enabled/disabled)
   * 
   * @param identityName
   *          the identity to query for
   * @param enableStatus
   *          whether the account shall be enabled (true) or disabled (false)
   * @return a list of all matching accounts
   */
  @GET
  @RequiredRight(value = SPRIGHT_ADMINISTRATOR_NAME)
  @Produces(MediaType.TEXT_PLAIN)
  @Path("accounts/{identityName}/enable/{enableStatus}")
  public Response enableAccount(@PathParam("identityName") String identityName, @PathParam("enableStatus") boolean enableStatus) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s, enableStatus %s)", "enableAccount", identityName, enableStatus));
    }
    
    boolean succeeded                = false;
    Connection connection            = null;
    PreparedStatement prepStatement  = null;
    try {
      connection    = getConnection();
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.UPDATE_ACCOUNT_ENABLED));
      prepStatement.setBoolean(1, enableStatus);
      prepStatement.setString(2, identityName);

      int countOfModifiedRows = prepStatement.executeUpdate();
      if(countOfModifiedRows > 0) {
        succeeded = true;
      }
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    } finally {
      if(prepStatement != null) {
        try {
          prepStatement.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
      if (connection != null) {
        try {
          connection.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "enableAccount", succeeded));
    }

    return Response.ok().entity(succeeded).build();
  }
  
  /**
   * enrolls an identity to mfa by starting the configured Workflow via a Service Request
   * @param identityName the identity to enroll
   * @param isAdmin whether to also provision the admin capability
   * @return true if there was no error invoking the request
   */
  @GET
  @RequiredRight(value = SPRIGHT_ADMINISTRATOR_NAME)
  @Produces(MediaType.TEXT_PLAIN)
  @Path("accounts/{identityName}/enroll/{isAdmin}")
  public Response enrollAccount(@PathParam("identityName") String identityName, @PathParam("isAdmin") boolean isAdmin) {
    if (_logger.isDebugEnabled()) {
      _logger
          .debug(String.format("ENTERING method %s(identityName %s, isAdmin %s)", "enrollAccount", identityName, isAdmin));
    }
    
    Boolean success           = false;
    long launchTime           = System.currentTimeMillis() + 60 * 1000;
    SailPointContext context  = null;
    RequestDefinition reqDef  = null;
    try {
      Boolean sendEmail     = PluginBaseHelper.getSettingBool(getPluginName(), "sendEnrollmentNotification");
      String template       = PluginBaseHelper.getSettingString(getPluginName(), "enrollmentNotificationTemplate");
      
      List<String> capList  = new ArrayList<>();
      capList.add(CAPABILITY_PLUGIN_ACCESS);
      if(isAdmin) {
        capList.add(CAPABILITY_PLUGIN_ADMIN);
      }
      context               = getContext();
      
      reqDef                = context.getObjectByName(RequestDefinition.class, "Workflow Request");
      Request request       = new Request(reqDef);
      String requestName    = String.format("Enroll user %s for multifactor authentication", new Object[]{identityName});
      
      request.setName(requestName);
      request.setAttribute("workflow", TINY_MFA_ENROLL_USER_WORKFLOW);
      request.setAttribute("informUserEmailTemplate", template);
      request.setAttribute("identityName", identityName);
      request.put("identityName", identityName);
      request.put("sendEmail", sendEmail);
      request.put("listOfCapabilities", capList);
      request.setNextLaunch(new Date(launchTime));

      context.saveObject(request);
      context.commitTransaction();
      success = true;
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
      success = false;
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "enrollAccount", success));
    }
    return Response.ok().entity(success).build();
  }

  /**
   * returns the requested account details
   * 
   * @param identityName
   *          the identity to query for
   * @return a list of all matching accounts
   */
  @GET
  @RequiredRight(value = SPRIGHT_ADMINISTRATOR_NAME)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("accounts/{identityName}")
  public Response getAccount(@PathParam("identityName") String identityName) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "getAccount", identityName));
    }

    List<Map<String, Object>> result = new ArrayList<>();
    Connection connection            = null;
    PreparedStatement prepStatement  = null;
    ResultSet resultSet              = null;
    try {
      connection    = getConnection();
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.SINGLE_ACCOUNT_QUERY));
      prepStatement.setString(1, identityName);

      resultSet = prepStatement.executeQuery();
      while (resultSet.next()) {
        Map<String, Object> accountObject = TinyMfaUtil.buildAccountObjectMap(resultSet);
        result.add(accountObject);
      }

      resultSet.close();
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    } finally {
      if(resultSet != null) {
        try {
          resultSet.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
      if(prepStatement != null) {
        try {
          prepStatement.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
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
   * returns basic identity information. Shown on the enrollment functionality
   * @param identityName the identity to be enrolled
   * @return a HashMap of the found identity information
   */
  @GET
  @RequiredRight(value = SPRIGHT_ADMINISTRATOR_NAME)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("identityInfo/{identityName}")
  public Response getIdentityInfo(@PathParam("identityName") String identityName) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "getIdentityInfo", identityName));
    }

    Map<String, Object> result = new HashMap<>();
    SailPointContext context   = null;
    try {
      context = getContext();
      Identity identity = context.getObject(Identity.class, identityName);
      if(identity != null) {
        String id = identity.getId();
        String name = identity.getName();
        String firstname = identity.getFirstname();
        String lastname  =identity.getLastname();
        String email = identity.getEmail();
        
        result.put("id", id);
        result.put("name", name);
        result.put("firstname", firstname);
        result.put("lastname", lastname);
        result.put("email", email);
      }
    } catch (GeneralException e) {
      _logger.error(e.getMessage());
    } 
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getIdentityInfo", result));
    }

    return Response.ok().entity(result).build();
  }

  /**
   * returns accounts from the database
   * 
   * @return a list of accounts
   */
  @GET
  @RequiredRight(value = SPRIGHT_ADMINISTRATOR_NAME)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("accounts")
  public Response getAccounts() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "getAccounts"));
    }

    List<Map<String, Object>> result = new ArrayList<>();
    Connection connection           = null;
    PreparedStatement prepStatement = null;
    ResultSet resultSet             = null;
    try {
      connection = getConnection();
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.ALL_ACCOUNTS_QUERY));

      resultSet = prepStatement.executeQuery();
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
      if(resultSet != null) {
        try {
          resultSet.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
      if(prepStatement != null) {
        try {
          prepStatement.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
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
  @RequiredRight(value = SPRIGHT_ADMINISTRATOR_NAME)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("audit")
  public Response getAudit() {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s()", "getAudit"));
    }

    List<Map<String, Object>> result  = new ArrayList<>();
    Connection connection             = null;
    PreparedStatement prepStatement   = null;
    ResultSet resultSet               = null;
    try {
      connection = getConnection();
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.AUDIT_QUERY, true));
      resultSet = prepStatement.executeQuery();
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
      if(resultSet != null) {
        try {
          resultSet.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
      if(prepStatement != null) {
        try {
          prepStatement.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
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
  
  /**
   * returns the validation attempts, limits the result to the supplied number
   * 
   * @param limit
   *          the limit of validation attempts to show
   * @return a list containing the validation attempts
   */
  @GET
  @RequiredRight(value = SPRIGHT_ADMINISTRATOR_NAME)
  @Produces(MediaType.APPLICATION_JSON)
  @Path("audit/{limit}")
  public Response getAuditWithLimit(@PathParam("limit") int limit) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(limit %s)", "getAuditWithLimit", limit));
    }

    List<Map<String, Object>> result  = new ArrayList<>();
    Connection connection             = null;
    PreparedStatement prepStatement   = null;
    ResultSet resultSet               = null;
    try {
      connection = getConnection();
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.AUDIT_QUERY, true));
      prepStatement.setInt(1, limit);
      
      resultSet = prepStatement.executeQuery();
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
      if(resultSet != null) {
        try {
          resultSet.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
      if(prepStatement != null) {
        try {
          prepStatement.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
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
    String qrCodeBase64   = null;
    String identityName   = null;
    String sanitizedName  = null;
    String bgColorHex     = PluginBaseHelper.getSettingString(getPluginName(), "bgColorHex");
    String fgColorHex     = PluginBaseHelper.getSettingString(getPluginName(), "fgColorHex");
    String issuer         = PluginBaseHelper.getSettingString(getPluginName(), "issuerDomain");
    
    // check colors. If, for any reasons, these values are empty, initialize with black/white
    if(bgColorHex == null || bgColorHex.isEmpty()) bgColorHex = "#FFF"; //background is white
    if(fgColorHex == null || fgColorHex.isEmpty()) bgColorHex = "#000"; //background is black
    
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
        qrCodeBase64 = TinyMfaUtil.generateBase64EncodedQrcode(qrCodeUrl, bgColorHex, fgColorHex);
      } catch (Exception e) {
        _logger.error(e.getMessage());
        hasError = true;
      }

    }

    if (_logger.isDebugEnabled()) {
      if(_logger.isTraceEnabled()) {
        _logger.trace(String.format("LEAVING method %s (returns: %s)", "getQrCodeData", qrCodeBase64));
      } else {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "getQrCodeData", "*** (masked)"));
      }
    }
    // return either an error or the qrCodeUrl
    return (hasError) ? Response.serverError().build() : Response.ok().entity(qrCodeBase64).build();
  }

  /**
   * returns whether the logged in user has the plugin admin capability assigned
   * @return true if the admin capability is assigned to the logged in user
   */
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
  public Boolean isValidToken(@PathParam("identityName") String identityName, @PathParam("token") String token) {
    if (_logger.isDebugEnabled()) {
      _logger
          .debug(String.format("ENTERING method %s(identityName %s, token %s)", "isValidToken", identityName, token));
    }

    SailPointContext context = getContext();

    // that's what we care for
    Boolean isAuthenticated = false;
    isAuthenticated         = isValidToken(identityName, token, context);

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "isValidToken", isAuthenticated));
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
  public Boolean isValidToken(String identityName, String token, SailPointContext context) {
    if (_logger.isDebugEnabled()) {
      _logger
          .debug(String.format("ENTERING method %s(identityName %s, token %s, context %s)", "isValidToken", identityName, token, context));
    }

    // that's what we care for
    Boolean isAuthenticated = false;
    Boolean isEnabled       = true;
    
    // get the current timestamp to generate the token
    long currentUnixTime    = TinyMfaImplementation.getValidMessageBySystemTimestamp();
    
    // check whether the account is disabled
    try {
      isEnabled = isAccountEnabled(identityName, context);
    } catch (GeneralException | SQLException e) {
      _logger.error(e.getMessage());
    }

    // only proceed if the account is enabled
    if (isEnabled) {
      // get the maximum attempts from the plugin settings
      int maximumAllowedValidationAttempts = PluginBaseHelper.getSettingInt(getPluginName(), "maxAttempts");

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

        } catch (Exception e) {
          _logger.error(e.getMessage());
        }
      } else {
        _logger.warn(String.format("number attempts (%s) exceeded limit %s for identity %s", attemptsForTimestamp,
            maximumAllowedValidationAttempts, identityName));
      }
    }
    
    // log the attempt
    try {
      insertValidationAttemptToDb(identityName, currentUnixTime, isEnabled, isAuthenticated);
    } catch (GeneralException | SQLException e) {
      _logger.error(e.getMessage());
    }

    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "isValidToken", isAuthenticated));
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
  private String createAccount(String identityName, SailPointContext context) throws GeneralException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s)", "createAccount", identityName));
    }

    // generate a new secret key. User must not be bothered with this
    String generatedPassword = null;
    String encryptedPassword = null;

    generatedPassword = TinyMfaImplementation.generateBase32EncodedSecretKey();
    encryptedPassword = context.encrypt(generatedPassword);
  

    Connection connection = getConnection();
    PreparedStatement prepStatement = null;;
    try {
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.CREATE_NEW_ACCOUNT));

      prepStatement.setString(1, identityName);
      prepStatement.setString(2, encryptedPassword);
      prepStatement.setBoolean(3, true);

      int resultCode = prepStatement.executeUpdate();
      if (resultCode != 0) {
      } else {
        throw new GeneralException("User could not be created");
      }
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } finally {
      if(prepStatement != null) {
        try {
          prepStatement.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
      
      if(connection != null) {
        try {
          connection.close();
        } catch (SQLException e) {
          _logger.error(e.getMessage());
        }
      }
      
    }


    

    if (_logger.isDebugEnabled()) {
      if(_logger.isTraceEnabled()) {
        _logger.trace(String.format("LEAVING method %s (returns: %s)", "createAccount", generatedPassword));
      } else {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "createAccount", "*** (masked)"));
      }
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
   * @param isEnabled
   *          is the account enabled
   * @param succeeded
   *          was the validation successful
   * @return
   * @throws GeneralException
   * @throws SQLException
   */
  private boolean insertValidationAttemptToDb(String identityName, long cts, boolean isEnabled, boolean succeeded)
      throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(identityName %s, cts %s, isEnabled %s, succeeded %s)",
          "insertValidationAttemptToDb", identityName, cts, isEnabled, succeeded));
    }

    boolean wasCompleted = false;

    Connection connection           = getConnection();
    PreparedStatement prepStatement = null;
    
    
    try {
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.AUDIT_VALIDATION_ATTEMPT));
      
      prepStatement.setLong(1, new java.util.Date().getTime());
      prepStatement.setLong(2, cts);
      prepStatement.setString(3, identityName);
      prepStatement.setBoolean(4, isEnabled);
      prepStatement.setBoolean(5, succeeded);

      int resultCode = prepStatement.executeUpdate();
      if (resultCode != 0) {
        wasCompleted = true;
      }
      
    } catch(Exception e) {
      _logger.error(e.getMessage());
      throw new GeneralException(e);
    } finally {
      if(prepStatement != null) {
        prepStatement.close();
      }
      
      if(connection != null) {
        connection.close();
      }
    }

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
  private Boolean isAccountEnabled(String identityName, SailPointContext context)
      throws GeneralException, SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(
          String.format("ENTERING method %s(identityName %s, context %s)", "isAccountEnabled", identityName, context));
    }
    boolean isEnabled               = true;
    Connection connection           = getConnection();
    PreparedStatement prepStatement = null;
    ResultSet resultSet             = null;
    try {
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.IS_ACCOUNT_ENABLED));
      prepStatement.setString(1, identityName);

      resultSet = prepStatement.executeQuery();
      if (resultSet.next()) {
        isEnabled = resultSet.getBoolean(1);
      }
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } finally {
      if(resultSet != null) {
        resultSet.close();
      }
      if(prepStatement != null) {
        prepStatement.close();
      }
      
      if(connection != null) {
        connection.close();
      }
    }


    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "isAccountEnabled", isEnabled));
    }

    return isEnabled;
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
    int result                      = 0;
    Connection connection           = getConnection();
    PreparedStatement prepStatement = null;
    ResultSet resultSet             = null;
    try {
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.COUNT_VALIDATION_ATTEMPTS));
      prepStatement.setString(1, identityName);
      prepStatement.setLong(2, cts);
      prepStatement.setBoolean(3, false);

      resultSet = prepStatement.executeQuery();
      if (resultSet.next()) {
        result = resultSet.getInt(1);
      }
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } finally {
      if(resultSet != null) {
        resultSet.close();
      }
      if(prepStatement != null) {
        prepStatement.close();
      }
      
      if(connection != null) {
        connection.close();
      }
    }

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
    String result                   = null;
    Connection connection           = getConnection();
    PreparedStatement prepStatement = null;
    ResultSet resultSet             = null;
    try {
      prepStatement = connection.prepareStatement(SqlSelectHelper.getValidQuery(connection, QUERY_TYPE.RETRIEVE_USER_PASSWORD));
      prepStatement.setString(1, identityName);

      resultSet = prepStatement.executeQuery();
      if (resultSet.next()) {
        String encryptedPassword = resultSet.getString(1);
        result = context.decrypt(encryptedPassword);
      }
    } catch (SQLException e) {
      _logger.error(e.getMessage());
    } finally {
      if(resultSet != null) {
        resultSet.close();
      }
      if(prepStatement != null) {
        prepStatement.close();
      }
      
      if(connection != null) {
        connection.close();
      }
    }

    if (_logger.isDebugEnabled()) {
      if(_logger.isTraceEnabled()) {
        _logger.trace(String.format("LEAVING method %s (returns: %s)", "returnPasswordFromDb", result));
      } else {
        _logger.debug(String.format("LEAVING method %s (returns: %s)", "returnPasswordFromDb", "*** (masked)"));
      }
    }
    return result;
  }
}