/**
 * 
 */
package de.whisperedshouts.tinymfa.util;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import org.apache.log4j.Logger;

/**
 * @author Mario Enrico Ragucci, mario@whisperedshouts.de
 *
 */
public class SqlSelectHelper {
  
  private static final Logger _logger     = Logger.getLogger(SqlSelectHelper.class);
  
  private static final String SQL_PRODUCT_NAME_ORACLE  = "Oracle";
  private static final String SQL_PRODUCT_NAME_DB2     = "DB2";
  private static final String SQL_PRODUCT_NAME_MSSQL   = "Microsoft SQL Server";
  private static final String SQL_PRODUCT_NAME_MYSQL   = "MySQL";
  
//check for failed validation attempts
  private static final String SQL_COUNT_VALIDATION_ATTEMPTS = "SELECT COUNT(*) FROM MFA_VALIDATION_ATTEMPTS WHERE CTS = ? and ACCOUNT_NAME = ? and SUCCEEDED = ?";

 //insert a new account into the database. This happens on first usage of the  plugin
  private static final String SQL_CREATE_NEW_ACCOUNT_QUERY = "INSERT INTO MFA_ACCOUNTS(ACCOUNT_NAME, USERPASSWORD, ISENABLED) VALUES(?,?,?)";
 
 //update the isDisabled setting of the account
  private static final String SQL_UPDATE_IS_ENABLED_STATUS = "UPDATE MFA_ACCOUNTS SET ISENABLED=? WHERE ACCOUNT_NAME=?";

 // insert a new validation attempt into the database
  private static final String SQL_INSERT_VALIDATION_ATTEMPT = "INSERT INTO MFA_VALIDATION_ATTEMPTS(ACCESS_TIME,CTS,ACCOUNT_NAME,ACCOUNT_ENABLED,SUCCEEDED) VALUES(?,?,?,?,?)";

 // check if user is disabled
  private static final String SQL_IS_ACCOUNT_ENABLED = "SELECT ISENABLED FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";

 // the SQL query used to retrieve the userkey from the database
  private static final String SQL_RETRIEVE_PASSWORD_QUERY = "SELECT USERPASSWORD FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";

 //select specific account attributes
  private static final String SQL_SELECT_ACCOUNT = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS WHERE ACCOUNT_NAME=?";
  
  public static enum QUERY_TYPE {
    COUNT_VALIDATION_ATTEMPTS,
    CREATE_NEW_ACCOUNT,
    IS_ACCOUNT_ENABLED,
    UPDATE_ACCOUNT_ENABLED,
    AUDIT_VALIDATION_ATTEMPT,
    RETRIEVE_USER_PASSWORD,
    SINGLE_ACCOUNT_QUERY,
    ALL_ACCOUNTS_QUERY,
    AUDIT_QUERY
  }
  
  /**
   * returns a query that is valid for the database type of the established connection
   * @param connection the connection object we derive the database type from
   * @param queryType the query to return
   * @param limitQuery whether or not this will be a limited query (e.g. returning a number of rows)
   * @return the query to be used in a prepared statement
   * @throws SQLException when there was an issue getting the connection details
   */
  public static String getValidQuery(Connection connection, QUERY_TYPE queryType, boolean limitQuery) throws SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(connection %s, queryType %s, limitQuery %s)", "getValidQuery", connection, queryType, limitQuery));
    }
    
    DatabaseMetaData metadata   = connection.getMetaData();
    String databaseProductName  = metadata.getDatabaseProductName();
    String result = null;
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("Got database type %s", databaseProductName));
    }
    
    switch(queryType) {
      case COUNT_VALIDATION_ATTEMPTS  : {
        result = SQL_COUNT_VALIDATION_ATTEMPTS;
        break;
      }
      case CREATE_NEW_ACCOUNT                : {
        result = SQL_CREATE_NEW_ACCOUNT_QUERY;
        break;
      }
      case IS_ACCOUNT_ENABLED         : {
        result = SQL_IS_ACCOUNT_ENABLED;
        break;
      }
      case UPDATE_ACCOUNT_ENABLED     : {
        result = SQL_UPDATE_IS_ENABLED_STATUS;
        break;
      }
      case AUDIT_VALIDATION_ATTEMPT  : {
        result = SQL_INSERT_VALIDATION_ATTEMPT;
        break;
      }
      case RETRIEVE_USER_PASSWORD     : {
        result = SQL_RETRIEVE_PASSWORD_QUERY;
        break;
      }
      case SINGLE_ACCOUNT_QUERY                 : {
        result = SQL_SELECT_ACCOUNT;
        break;
      }
      case ALL_ACCOUNTS_QUERY                : {
        switch(databaseProductName) {
          case SQL_PRODUCT_NAME_ORACLE : result = doOracleDbLookup(connection, queryType, limitQuery); break;
          case SQL_PRODUCT_NAME_DB2    : result = doDb2DbLookup(connection,    queryType, limitQuery); break;
          case SQL_PRODUCT_NAME_MSSQL  : result = doMssqlDbLookup(connection,  queryType, limitQuery); break;
          case SQL_PRODUCT_NAME_MYSQL  : result = doMysqlDbLookup(connection,  queryType, limitQuery); break;
          default: _logger.error("could not determine database product - Probably unsupported database type " + databaseProductName);
        }
        break;
      }
      case AUDIT_QUERY                : {
        switch(databaseProductName) {
          case SQL_PRODUCT_NAME_ORACLE : result = doOracleDbLookup(connection, queryType, limitQuery); break;
          case SQL_PRODUCT_NAME_DB2    : result = doDb2DbLookup(connection,    queryType, limitQuery); break;
          case SQL_PRODUCT_NAME_MSSQL  : result = doMssqlDbLookup(connection,  queryType, limitQuery); break;
          case SQL_PRODUCT_NAME_MYSQL  : result = doMysqlDbLookup(connection,  queryType, limitQuery); break;
          default: _logger.error("could not determine database product - Probably unsupported database type " + databaseProductName);
        }
        break;
      }
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getValidQuery", result));
    }   
    return result;
  }
  
  /**
   * returns a query that is valid for the database type of the established connection
   * @param connection the connection object we derive the database type from
   * @param queryType the query to return
   * @return the query to be used in a prepared statement
   * @throws SQLException when there was an issue getting the connection details
   */
  public static String getValidQuery(Connection connection, QUERY_TYPE queryType) throws SQLException {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(connection %s, queryType %s)", "getValidQuery", connection, queryType));
    }
    
    String result = getValidQuery(connection, queryType, false);
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "getValidQuery", result));
    }   
    return result;
  }

  /**
   * returns a query that is valid for the database type of the established connection
   * @param connection the connection object we derive the database type from
   * @param queryType the query to return
   * @param limitQuery whether or not this will be a limited query (e.g. returning a number of rows)
   * @return the query to be used in a prepared statement
   * @throws SQLException when there was an issue getting the connection details
   */
  private static String doOracleDbLookup(Connection connection, QUERY_TYPE queryType, boolean limitQuery) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(connection %s, queryType %s, limitQuery %s)", "doOracleDbLookup", connection, queryType, limitQuery));
    }
    String result = null;
    switch(queryType) {
      case AUDIT_QUERY : {
        if(limitQuery) {
          result = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS WHERE ROWNUM <= ? ORDER BY ID DESC";
        } else {
          result = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC";
        }
        break;
      }
      case ALL_ACCOUNTS_QUERY:   {
        if(limitQuery) {
          result = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS WHERE ROWNUM <= ?";
        } else {
          result = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS";
        }
        break;
      }
      default:
        _logger.warn("we encountered a queryType that should not have been queried by this tool: " + queryType);
        break;
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "doOracleDbLookup", result));
    }   
    return result;
  }
  
  /**
   * returns a query that is valid for the database type of the established connection
   * @param connection the connection object we derive the database type from
   * @param queryType the query to return
   * @param limitQuery whether or not this will be a limited query (e.g. returning a number of rows)
   * @return the query to be used in a prepared statement
   * @throws SQLException when there was an issue getting the connection details
   */
  private static String doDb2DbLookup(Connection connection, QUERY_TYPE queryType, boolean limitQuery) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(connection %s, queryType %s, limitQuery %s)", "doDb2DbLookup", connection, queryType, limitQuery));
    }
    String result = null;
    switch(queryType) {
      case AUDIT_QUERY : {
        if(limitQuery) {
          result = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC fetch first ? rows only";
        } else {
          result = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC";
        }
        break;
      }
      case ALL_ACCOUNTS_QUERY:   {
        if(limitQuery) {
          result = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS fetch first ? rows only";
        } else {
          result = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS";
        }
        break;
      }
      default:
        _logger.warn("we encountered a queryType that should not have been queried by this tool: " + queryType);
        break;
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "doDb2DbLookup", result));
    }   
    return result;
  }
  
  /**
   * returns a query that is valid for the database type of the established connection
   * @param connection the connection object we derive the database type from
   * @param queryType the query to return
   * @param limitQuery whether or not this will be a limited query (e.g. returning a number of rows)
   * @return the query to be used in a prepared statement
   * @throws SQLException when there was an issue getting the connection details
   */
  private static String doMssqlDbLookup(Connection connection, QUERY_TYPE queryType, boolean limitQuery) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(connection %s, queryType %s, limitQuery %s)", "doMssqlDbLookup", connection, queryType, limitQuery));
    }
    String result = null;
    switch(queryType) {
      case AUDIT_QUERY : {
        if(limitQuery) {
          result = "SELECT TOP (?) ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC";
        } else {
          result = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC";
        }
        
        break;
      }
      case ALL_ACCOUNTS_QUERY:   {
        if(limitQuery) {
          result = "SELECT TOP (?) ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS";
        } else {
          result = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS";
        }
        break;
      }
      default:
        _logger.warn("we encountered a queryType that should not have been queried by this tool: " + queryType);
        break;
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "doMssqlDbLookup", result));
    }   
    return result;
  }
  
  /**
   * returns a query that is valid for the database type of the established connection
   * @param connection the connection object we derive the database type from
   * @param queryType the query to return
   * @param limitQuery whether or not this will be a limited query (e.g. returning a number of rows)
   * @return the query to be used in a prepared statement
   * @throws SQLException when there was an issue getting the connection details
   */
  private static String doMysqlDbLookup(Connection connection, QUERY_TYPE queryType, boolean limitQuery) {
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("ENTERING method %s(connection %s, queryType %s, limitQuery %s)", "doMysqlDbLookup", connection, queryType, limitQuery));
    }
    String result = null;
    switch(queryType) {
      case AUDIT_QUERY : {
        if(limitQuery) {
          result = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC LIMIT ?";
        } else {
          result = "SELECT ID, ACCESS_TIME, CTS, ACCOUNT_NAME, ACCOUNT_ENABLED, SUCCEEDED FROM MFA_VALIDATION_ATTEMPTS ORDER BY ID DESC";
        }
        break;
      }
      case ALL_ACCOUNTS_QUERY:   {
        if(limitQuery) {
          result = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS LIMIT ?";
        } else {
          result = "SELECT ID, ACCOUNT_NAME, ISENABLED FROM MFA_ACCOUNTS";
        }
        break;
      }
      default:
        _logger.warn("we encountered a queryType that should not have been queried by this tool: " + queryType);
        break;
    }
    
    if (_logger.isDebugEnabled()) {
      _logger.debug(String.format("LEAVING method %s (returns: %s)", "doMysqlDbLookup", result));
    }   
    return result;
  }
}
