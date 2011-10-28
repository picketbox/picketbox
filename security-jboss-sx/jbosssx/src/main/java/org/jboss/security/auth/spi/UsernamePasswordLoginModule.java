/*
* JBoss, Home of Professional Open Source
* Copyright 2005, JBoss Inc., and individual contributors as indicated
* by the @authors tag. See the copyright.txt in the distribution for a
* full listing of individual contributors.
*
* This is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 2.1 of
* the License, or (at your option) any later version.
*
* This software is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this software; if not, write to the Free
* Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
* 02110-1301 USA, or see the FSF site: http://www.fsf.org.
*/
package org.jboss.security.auth.spi;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.jboss.crypto.digest.DigestCallback;
import org.jboss.security.ErrorCodes;


/** An abstract subclass of AbstractServerLoginModule that imposes
 * an identity == String username, credentials == String password view on
 * the login process.
 * <p>
 * Subclasses override the <code>getUsersPassword()</code>
 * and <code>getRoleSets()</code> methods to return the expected password and roles
 * for the user.
 *
 * @see #getUsername()
 * @see #getUsersPassword()
 * @see #getRoleSets()
 * @see #createIdentity(String)
 
 @author Scott.Stark@jboss.org
 @version $Revision$
 */
public abstract class UsernamePasswordLoginModule extends AbstractServerLoginModule
{
   /** The login identity */
   private Principal identity;
   /** The proof of login identity */
   private char[] credential;
   /** the message digest algorithm used to hash passwords. If null then
    plain passwords will be used. */
   private String hashAlgorithm = null;
  /** the name of the charset/encoding to use when converting the password
   String to a byte array. Default is the platform's default encoding.
   */
   private String hashCharset = null;
   /** the string encoding format to use. Defaults to base64. */
   private String hashEncoding = null;
   /** A flag indicating if the password comparison should ignore case */
   private boolean ignorePasswordCase;
   /** A flag indicating if the store password should be hashed using the hashAlgorithm  */
   private boolean hashStorePassword;

   /** A flag indicating if the user supplied password should be hashed using the hashAlgorithm */
   private boolean hashUserPassword = true;
   /** A flag that restores the ability to override the createPasswordHash(String,String) */
   private boolean legacyCreatePasswordHash;
   
   /** A flag that indicates whether validation errors should be exposed to clients or not */
   private boolean throwValidateError = false;
   /** A {@code Throwable} representing the validation error */
   private Throwable validateError; 

   /** The input validator instance used to validate the username and password supplied by the client. */
   private InputValidator inputValidator = null;
   
   /** Override the superclass method to look for the following options after
    first invoking the super version.
    @param options :
    option: hashAlgorithm - the message digest algorithm used to hash passwords.
    If null then plain passwords will be used.
    option: hashCharset - the name of the charset/encoding to use when converting
    the password String to a byte array. Default is the platform's default
    encoding.
    option: hashEncoding - the string encoding format to use. Defaults to base64.
    option: ignorePasswordCase: A flag indicating if the password comparison
      should ignore case.
    option: digestCallback - The class name of the DigestCallback {@link org.jboss.crypto.digest.DigestCallback}
      implementation that includes pre/post digest content like salts for hashing
      the input password. Only used if hashAlgorithm has been specified.
    option: hashStorePassword - A flag indicating if the store password returned
      from #getUsersPassword() should be hashed .
    option: hashUserPassword - A flag indicating if the user entered password should be hashed.
    option: storeDigestCallback - The class name of the DigestCallback {@link org.jboss.crypto.digest.DigestCallback}
      implementation that includes pre/post digest content like salts for hashing
      the store/expected password. Only used if hashStorePassword or hashUserPassword is true and
      hashAlgorithm has been specified.
    */
   @Override
   public void initialize(Subject subject, CallbackHandler callbackHandler,
      Map<String,?> sharedState, Map<String,?> options)
   {
      super.initialize(subject, callbackHandler, sharedState, options);

      // Check to see if password hashing has been enabled.
      // If an algorithm is set, check for a format and charset.
      hashAlgorithm = (String) options.get("hashAlgorithm");
      if( hashAlgorithm != null )
      {
         hashEncoding = (String) options.get("hashEncoding");
         if( hashEncoding == null )
            hashEncoding = Util.BASE64_ENCODING;
         hashCharset = (String) options.get("hashCharset");
         if( log.isTraceEnabled() )
         {
            log.trace("Password hashing activated: algorithm = " + hashAlgorithm
               + ", encoding = " + hashEncoding
               + ", charset = " + (hashCharset == null ? "{default}" : hashCharset)
               + ", callback = " + options.get("digestCallback")
               + ", storeCallback = " + options.get("storeDigestCallback")
            );
         }
      }
      String flag = (String) options.get("ignorePasswordCase");
      ignorePasswordCase = Boolean.valueOf(flag).booleanValue();
      flag = (String) options.get("hashStorePassword");
      hashStorePassword = Boolean.valueOf(flag).booleanValue();
      flag = (String) options.get("hashUserPassword");
      if( flag != null )
         hashUserPassword = Boolean.valueOf(flag).booleanValue();
      flag = (String) options.get("legacyCreatePasswordHash");
      if( flag != null )
         legacyCreatePasswordHash = Boolean.valueOf(flag).booleanValue();
      flag = (String) options.get("throwValidateError");
      if(flag != null)
         this.throwValidateError = Boolean.valueOf(flag).booleanValue();
      // instantiate the input validator class.
      flag = (String) options.get("inputValidator");
      if(flag != null)
      {
         try
         {
            Class<?> validatorClass = SecurityActions.loadClass(flag); 
            this.inputValidator = (InputValidator) validatorClass.newInstance();
         }
         catch(Exception e)
         {
            this.log.debug("Unable to instantiate input validator class: " + flag);
         }
      }
   }

   /** Perform the authentication of the username and password.
    */
   @Override
   @SuppressWarnings("unchecked")
   public boolean login() throws LoginException
   {
      // See if shared credentials exist
      if( super.login() == true )
      {
         // Setup our view of the user
         Object username = sharedState.get("javax.security.auth.login.name");
         if( username instanceof Principal )
            identity = (Principal) username;
         else
         {
            String name = username.toString();
            try
            {
               identity = createIdentity(name);
            }
            catch(Exception e)
            {
               log.debug("Failed to create principal", e);
               throw new LoginException(ErrorCodes.PROCESSING_FAILED  + "Failed to create principal: "+ e.getMessage());
            }
         }
         Object password = sharedState.get("javax.security.auth.login.password");
         if( password instanceof char[] )
            credential = (char[]) password;
         else if( password != null )
         {
            String tmp = password.toString();
            credential = tmp.toCharArray();
         }
         return true;
      }

      super.loginOk = false;
      String[] info = getUsernameAndPassword();
      String username = info[0];
      String password = info[1];
      
      // validate the retrieved username and password.
      if(this.inputValidator != null)
      {
         try
         {
            this.inputValidator.validateUsernameAndPassword(username, password);
         }
         catch(InputValidationException ive)
         {
            throw new FailedLoginException(ive.getMessage());
         }
      }

      if( username == null && password == null )
      {
         identity = unauthenticatedIdentity;
         super.log.trace("Authenticating as unauthenticatedIdentity="+identity);
      }

      if( identity == null )
      {
         try
         {
            identity = createIdentity(username);
         }
         catch(Exception e)
         {
            log.debug("Failed to create principal", e);
            throw new LoginException(ErrorCodes.PROCESSING_FAILED + "Failed to create principal: "+ e.getMessage());
         }

         // Hash the user entered password if password hashing is in use
         if( hashAlgorithm != null && hashUserPassword == true )
            password = createPasswordHash(username, password, "digestCallback");
         // Validate the password supplied by the subclass
         String expectedPassword = getUsersPassword();
         // Allow the storeDigestCallback to hash the expected password
         if( hashAlgorithm != null && hashStorePassword == true )
            expectedPassword = createPasswordHash(username, expectedPassword, "storeDigestCallback");
         if( validatePassword(password, expectedPassword) == false )
         {
            Throwable ex = getValidateError();
            FailedLoginException fle = new FailedLoginException("Password Incorrect/Password Required");
            if( ex != null && this.throwValidateError == true)
            {
               log.debug("Bad password for username="+username, ex);
               fle.initCause(ex);
            }
            else
            {
               log.debug("Bad password for username="+username);
            }
            throw fle;
         }
      }

      if( getUseFirstPass() == true )
      {    // Add the principal and password to the shared state map
         sharedState.put("javax.security.auth.login.name", identity);
         sharedState.put("javax.security.auth.login.password", credential);
      }
      super.loginOk = true;
      super.log.trace("User '" + identity + "' authenticated, loginOk="+loginOk);
      return true;
   }

   @Override
   protected Principal getIdentity()
   {
      return identity;
   }
   @Override
   protected Principal getUnauthenticatedIdentity()
   {
      return unauthenticatedIdentity;
   }

   protected Object getCredentials()
   {
      return credential;
   }
   protected String getUsername()
   {
      String username = null;
      if( getIdentity() != null )
         username = getIdentity().getName();
      return username;
   }

   /** Called by login() to acquire the username and password strings for
    authentication. This method does no validation of either.
    @return String[], [0] = username, [1] = password
    @exception LoginException thrown if CallbackHandler is not set or fails.
    */
   protected String[] getUsernameAndPassword() throws LoginException
   {
      String[] info = {null, null};
      // prompt for a username and password
      if( callbackHandler == null )
      {
         throw new LoginException(ErrorCodes.NULL_VALUE + "Error: no CallbackHandler available " +
         "to collect authentication information");
      }
      
      NameCallback nc = new NameCallback("User name: ", "guest");
      PasswordCallback pc = new PasswordCallback("Password: ", false);
      Callback[] callbacks = {nc, pc};
      String username = null;
      String password = null;
      try
      {
         callbackHandler.handle(callbacks);
         username = nc.getName();
         char[] tmpPassword = pc.getPassword();
         if( tmpPassword != null )
         {
            credential = new char[tmpPassword.length];
            System.arraycopy(tmpPassword, 0, credential, 0, tmpPassword.length);
            pc.clearPassword();
            password = new String(credential);
         }
      }
      catch(IOException e)
      {
         LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Failed to get username/password");
         le.initCause(e);
         throw le;
      }
      catch(UnsupportedCallbackException e)
      {
         LoginException le = new LoginException(ErrorCodes.UNRECOGNIZED_CALLBACK + "CallbackHandler does not support: " + e.getCallback());
         le.initCause(e);
         throw le;
      }
      info[0] = username;
      info[1] = password;
      return info;
   }

  /**
   * If hashing is enabled, this method is called from <code>login()</code>
   * prior to password validation.
   * <p>
   * Subclasses may override it to provide customized password hashing,
   * for example by adding user-specific information or salting. If the
   * legacyCreatePasswordHash option is set, this method tries to delegate
   * to the legacy createPasswordHash(String, String) method via reflection
   * and this is the value returned.
   * <p>
   * The default version calculates the hash based on the following options:
   * <ul>
   * <li><em>hashAlgorithm</em>: The digest algorithm to use.
   * <li><em>hashEncoding</em>: The format used to store the hashes (base64 or hex)
   * <li><em>hashCharset</em>: The encoding used to convert the password to bytes
   * for hashing.
   * <li><em>digestCallback</em>: The class name of the
   * org.jboss.security.auth.spi.DigestCallback implementation that includes
   * pre/post digest content like salts.
   * </ul>
   * It will return null if the hash fails for any reason, which will in turn
   * cause <code>validatePassword()</code> to fail.
   * 
   * @param username ignored in default version
   * @param password the password string to be hashed
   * @param digestOption - the login module option name of the DigestCallback
   * @throws SecurityException - thrown if there is a failure to load the
   *  digestOption DigestCallback
   */
   @SuppressWarnings("unchecked")
   protected String createPasswordHash(String username, String password,
     String digestOption)
     throws LoginException
   {
      // Support for 4.0.2 createPasswordHash(String, String) override
      if( legacyCreatePasswordHash )
      {
         try
         {
            // Try to invoke the subclass createPasswordHash(String, String)
            Class<?>[] sig = {String.class, String.class};
            Method createPasswordHash = getClass().getMethod("createPasswordHash", sig);
            Object[] args = {username, password};
            String passwordHash = (String) createPasswordHash.invoke(this, args);
            return passwordHash;
         }
         catch (InvocationTargetException e)
         {
            LoginException le = new LoginException("Failed to delegate createPasswordHash");
            le.initCause(e.getTargetException());
            throw le;
         }
         catch(Exception e)
         {
            LoginException le = new LoginException("Failed to delegate createPasswordHash");
            le.initCause(e);
            throw le;            
         }
      }

      DigestCallback callback = null;
      String callbackClassName = (String) options.get(digestOption);
      if( callbackClassName != null )
      {
         try
         {
            Class<?> callbackClass = SecurityActions.loadClass(callbackClassName);
            callback = (DigestCallback) callbackClass.newInstance();
            if( log.isTraceEnabled() )
               log.trace("Created DigestCallback: "+callback);
         }
         catch (Exception e)
         {
            if( log.isTraceEnabled() )
               log.trace("Failed to load DigestCallback", e);
            SecurityException ex = new SecurityException("Failed to load DigestCallback");
            ex.initCause(e);
            throw ex;
         }
         Map<String,Object> tmp = new HashMap<String,Object>();
         tmp.putAll(options);
         tmp.put("javax.security.auth.login.name", username);
         tmp.put("javax.security.auth.login.password", password);

         callback.init(tmp);
         // Check for a callbacks
         Callback[] callbacks = (Callback[]) tmp.get("callbacks");
         if( callbacks != null )
         {
            try
            {
               callbackHandler.handle(callbacks);
            }
            catch(IOException e)
            {
               LoginException le = new LoginException(digestOption+" callback failed");
               le.initCause(e);
               throw le;
            }
            catch(UnsupportedCallbackException e)
            {
               LoginException le = new LoginException(digestOption+" callback failed");
               le.initCause(e);
               throw le;
            }
         }
      }
      String passwordHash = Util.createPasswordHash(hashAlgorithm, hashEncoding,
         hashCharset, username, password, callback);
      return passwordHash;
   }

   /**
    * Get the error associated with the validatePassword failure
    * @return the Throwable seen during validatePassword, null if no
    * error occurred.
    */
   protected Throwable getValidateError()
   {
      return validateError;
   }

   /**
    * Set the error associated with the validatePassword failure
    * @param validateError
    */
   protected void setValidateError(Throwable validateError)
   {
      this.validateError = validateError;
   }

   /** A hook that allows subclasses to change the validation of the input
    password against the expected password. This version checks that
    neither inputPassword or expectedPassword are null that that
    inputPassword.equals(expectedPassword) is true;
    @return true if the inputPassword is valid, false otherwise.
    */
   protected boolean validatePassword(String inputPassword, String expectedPassword)
   {
      if( inputPassword == null || expectedPassword == null )
         return false;
      boolean valid = false;
      if( ignorePasswordCase == true )
         valid = inputPassword.equalsIgnoreCase(expectedPassword);
      else
         valid = inputPassword.equals(expectedPassword);
      return valid;
   }


   /** Get the expected password for the current username available via
    the getUsername() method. This is called from within the login()
    method after the CallbackHandler has returned the username and
    candidate password.
    @return the valid password String
    */
   abstract protected String getUsersPassword() throws LoginException;
   
}
