/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
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
package org.jboss.security.auth.spi.otp;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import org.jboss.logging.Logger;
import org.jboss.security.otp.TimeBasedOTP;
import org.jboss.security.otp.TimeBasedOTPUtil;

/**
 * <p>
 * Login Module that can be configured to validate a Time based OTP.
 * </p>
 * 
 * <p>
 * Usage:
 * This login module needs to be configured along with one of the other JBoss login modules such
 * as {@code org.jboss.security.auth.spi.DatabaseServerLoginModule} or
 * {@code org.jboss.security.auth.spi.LdapLoginModule}
 * </p>
 * Example configuration:
 * <p>
 * <pre>
 * {@code
 * <application-policy name="otp">
    <authentication>
      <login-module code="org.jboss.security.auth.spi.UsersRolesLoginModule"
        flag="required">
        <module-option name="usersProperties">props/jmx-console-users.properties</module-option>
        <module-option name="rolesProperties">props/jmx-console-roles.properties</module-option>
      </login-module>
      <login-module code="org.jboss.security.auth.spi.otp.JBossTimeBasedOTPLoginModule" />
    </authentication>
  </application-policy>
 * }
 * </pre>
 * </p>
 * 
 * <p>
 * Configurable Options:
 * </p>
 * <p>
 * <ul>
 * <li>algorithm:  either "HmacSHA1", "HmacSHA256" or "HmacSHA512"   [Default: "HmacSHA1"]</li>
 * <li>numOfDigits:  Number of digits in the TOTP.  Default is 6.</li>
 * </ul>
 * </p>
 * 
 * <p>
 * This login module requires the presence of "otp-users.properties" on the class path with the format:
 * username=key
 * </p>
 * 
 * <p>
 * An example of otp-users.properties is:
 * </p>
 * <p>
 * <pre>
    admin=35cae61d6d51a7b3af
   </pre>
 * </p>
 * 
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Sep 21, 2010
 */
public class JBossTimeBasedOTPLoginModule implements LoginModule
{  
   private static Logger log = Logger.getLogger( JBossTimeBasedOTPLoginModule.class );
   private boolean trace = log.isTraceEnabled();

   public static final String TOTP = "totp";

   private Map<String,Object> lmSharedState = new HashMap<String,Object>();
   private Map<String, Object> lmOptions = new HashMap<String,Object>(); 
   private CallbackHandler callbackHandler;
   private boolean useFirstPass;

   //This is the number of digits in the totp
   private int NUMBER_OF_DIGITS = 6;
   
   /**
    * Default algorithm is HMAC_SHA1
    */
   private String algorithm = TimeBasedOTP.HMAC_SHA1; //Default

   public void initialize( Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
         Map<String, ?> options )
   { 
      this.callbackHandler = callbackHandler;
      this.lmSharedState.putAll( sharedState );
      this.lmOptions.putAll( options );

      /* Check for password sharing options. Any non-null value for
      password_stacking sets useFirstPass as this module has no way to
      validate any shared password.
       */
      String passwordStacking = (String) options.get("password-stacking");
      if( passwordStacking != null && passwordStacking.equalsIgnoreCase("useFirstPass") )
         useFirstPass = true;
      
      //Option for number of digits
      String numDigitString = (String) options.get( "numOfDigits" );
      if( numDigitString != null && numDigitString.length() > 0 )
         NUMBER_OF_DIGITS = Integer.parseInt( numDigitString );
      
      //Algorithm
      String algorithmStr = (String) options.get( "algorithm" );
      if( algorithmStr != null && algorithmStr != "" )
      {
         if( algorithmStr.equalsIgnoreCase( TimeBasedOTP.HMAC_SHA256) )
            algorithm = TimeBasedOTP.HMAC_SHA256;
         if( algorithmStr.equalsIgnoreCase( TimeBasedOTP.HMAC_SHA512 ))
            algorithm = TimeBasedOTP.HMAC_SHA512;
      }
   }

   /**
    * @see {@code LoginModule#login()}
    */
   public boolean login() throws LoginException
   {
      String username = null;
       

      if( useFirstPass == true )
      {
         username = (String) lmSharedState.get("javax.security.auth.login.name");  
      }
      else
      { 
         NameCallback nc = new NameCallback("User name: ", "guest"); 
         Callback[] callbacks = { nc };
         try
         {
            callbackHandler.handle(callbacks);
         }
         catch ( Exception e )
         {
            LoginException le = new LoginException();
            le.initCause( e );
            throw le;
         } 

         username = nc.getName();
      }
      
      //Load the otp-users.properties file
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      InputStream is = tcl.getResourceAsStream( "otp-users.properties" );
      
      Properties otp = new Properties();
      try
      {
         otp.load( is );
      }
      catch (IOException e )
      {
         LoginException le = new LoginException( "Unable to load the otp users properties");
         le.initCause( e );
         throw le;
      }
      
      String seed = otp.getProperty( username );

      String submittedTOTP = this.getTimeBasedOTPFromRequest();
      if( submittedTOTP == null || submittedTOTP.length() == 0 )
      {
         if( trace )
         {
            log.trace( "Either the TOTP in request was null or was of zero length::TOTP=" + submittedTOTP );
         }
         throw new LoginException(); 
      }
  
      try
      {
         boolean result =  false;
         
         if( algorithm.equals( TimeBasedOTP.HMAC_SHA1 ))
         {
            result =  TimeBasedOTPUtil.validate( submittedTOTP, seed.getBytes() , NUMBER_OF_DIGITS ); 
         }
         else if( algorithm.equals( TimeBasedOTP.HMAC_SHA256 ))
         {
            result =  TimeBasedOTPUtil.validate256( submittedTOTP, seed.getBytes() , NUMBER_OF_DIGITS ); 
         }
         else if( algorithm.equals( TimeBasedOTP.HMAC_SHA512 ))
         {
            result =  TimeBasedOTPUtil.validate512( submittedTOTP, seed.getBytes() , NUMBER_OF_DIGITS ); 
         }
         
         if( result == false )
            throw new LoginException();
         
         return result; 
      }
      catch (GeneralSecurityException e)
      {
         LoginException le = new LoginException();
         le.initCause( e );
         throw le;
      } 
   }

   /**
    * @see {@code LoginModule#commit()}
    */
   public boolean commit() throws LoginException
   { 
      return true;
   }

   /**
    * @see {@code LoginModule#abort()}
    */
   public boolean abort() throws LoginException
   { 
      return true;
   }

   /**
    * @see {@code LoginModule#logout()}
    */
   public boolean logout() throws LoginException
   { 
      return true;
   } 

   private String getTimeBasedOTPFromRequest()
   {
      String totp = null;

      //This is JBoss AS specific mechanism 
      String WEB_REQUEST_KEY = "javax.servlet.http.HttpServletRequest";

      try
      {
         HttpServletRequest request = (HttpServletRequest) PolicyContext.getContext(WEB_REQUEST_KEY);
         totp = request.getParameter( TOTP );
      }
      catch (PolicyContextException e)
      {
         if( log.isTraceEnabled() )
         {
            log.trace( "Error getting request::", e ); 
         } 
      }
      return totp; 
   }
}