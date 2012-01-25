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
package org.jboss.security;


import java.security.Principal;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jboss.logging.Logger;

/** A simple implementation of LoginModule for use by JBoss clients for
 the establishment of the caller identity and credentials. This simply sets
 the SecurityAssociation principal to the value of the NameCallback
 filled in by the CallbackHandler, and the SecurityAssociation credential
 to the value of the PasswordCallback filled in by the CallbackHandler.
 This is a variation of the original ClientLoginModule that does not set the
 SecurityAssociation information until commit and that uses the Subject
 principal over a SimplePrincipal if available.

 It has the following options:
 <ul>
 <li>multi-threaded=[true|false]
 When the multi-threaded option is set to true, the SecurityAssociation.setServer()
 so that each login thread has its own principal and credential storage.
 <li>password-stacking=tryFirstPass|useFirstPass
 When password-stacking option is set, this module first looks for a shared
 username and password using "javax.security.auth.login.name" and
 "javax.security.auth.login.password" respectively. This allows a module configured
 prior to this one to establish a valid username and password that should be passed
 to JBoss.
 </ul>
 
 @author Scott.Stark@jboss.org
 @version $Revision$
 */
public class AltClientLoginModule implements LoginModule
{
   private static Logger log = Logger.getLogger(AltClientLoginModule.class);
   private Subject subject;
   private CallbackHandler callbackHandler;
   /** Shared state between login modules */
   private Map<String,?> sharedState;
   /** Flag indicating if the shared password should be used */
   private boolean useFirstPass;
   private String username;
   private char[] password = null;
   private boolean trace;

   /**
    * Initialize this LoginModule.
    */
   public void initialize(Subject subject, CallbackHandler callbackHandler,
      Map<String,?> sharedState, Map<String,?> options)
   {
      this.trace = log.isTraceEnabled();
      this.subject = subject;
      this.callbackHandler = callbackHandler;
      this.sharedState = sharedState;

      //log securityDomain, if set.
      if(trace)
	    log.trace("Security domain: " + 
		   (String)options.get(SecurityConstants.SECURITY_DOMAIN_OPTION));

      // Check for multi-threaded option
      String mt = (String) options.get("multi-threaded");
      if( Boolean.valueOf(mt).booleanValue() == true )
      { 
	 /* Turn on the server mode which uses thread local storage for
	    the principal information.
         */
         if(trace)
            log.trace("Enabling multi-threaded mode");
      }
      
        /* Check for password sharing options. Any non-null value for
            password_stacking sets useFirstPass as this module has no way to
            validate any shared password.
         */
      String passwordStacking = (String) options.get("password-stacking");
      useFirstPass = passwordStacking != null;
      if(trace && useFirstPass)
	    log.trace("Enabling useFirstPass mode");
   }

   /**
    * Method to authenticate a Subject (phase 1).
    */
   public boolean login() throws LoginException
   {
      // If useFirstPass is true, look for the shared password
      if( useFirstPass == true )
      {
            return true;
      }

     /* There is no password sharing or we are the first login module. Get
         the username and password from the callback hander.
      */
      if (callbackHandler == null)
         throw new LoginException(ErrorCodes.NULL_VALUE + "Error: no CallbackHandler available " +
            "to garner authentication information from the user");
      
      PasswordCallback pc = new PasswordCallback("Password: ", false);
      NameCallback nc = new NameCallback("User name: ", "guest");
      Callback[] callbacks = {nc, pc};
      try
      {
         char[] tmpPassword;
         
         callbackHandler.handle(callbacks);
         username = nc.getName();
         tmpPassword = pc.getPassword();
         if (tmpPassword != null)
         {
            password = new char[tmpPassword.length];
            System.arraycopy(tmpPassword, 0, password, 0, tmpPassword.length);
            pc.clearPassword();
         }
      }
      catch (java.io.IOException ioe)
      {
         throw new LoginException(ioe.toString());
      }
      catch (UnsupportedCallbackException uce)
      {
         throw new LoginException(ErrorCodes.WRONG_TYPE + "Error: " + uce.getCallback().toString() +
         " not available to garner authentication information " +
         "from the user");
      }
      return true;
   }

   /** Method to commit the authentication process (phase 2). This is where the
    * SecurityAssociation information is set. The principal is obtained from:
    * The shared state javax.security.auth.login.name property when useFirstPass
    * is true. If the value is a Principal it is used as is, else a SimplePrincipal
    * using the value.toString() as its name is used. If useFirstPass the
    * username obtained from the callback handler is used to build the
    * SimplePrincipal. Both may be overriden if the resulting authenticated
    * Subject principals set it not empty.
    * 
    */
   public boolean commit() throws LoginException
   {
      Set<Principal> principals = subject.getPrincipals();
      Principal p = null;
      Object credential = password;
      if( useFirstPass == true )
      {
         Object user = sharedState.get("javax.security.auth.login.name");
         if( (user instanceof Principal) == false )
         {
            username = user != null ? user.toString() : "";
            p = new SimplePrincipal(username);
         }
         else
         {
            p = (Principal) user;
         }
         credential = sharedState.get("javax.security.auth.login.password");
      }
      else
      {
         p = new SimplePrincipal(username);
      }

      if( principals.isEmpty() == false )
         p = (Principal) principals.iterator().next();
      SecurityAssociationActions.setPrincipalInfo(p, credential, subject);
      return true;
   }

   /**
    * Method to abort the authentication process (phase 2).
    */
   public boolean abort() throws LoginException
   {
      int length = password != null ? password.length : 0;
      for(int n = 0; n < length; n ++)
         password[n] = 0;
      SecurityAssociationActions.clear();
      return true;
   }

   public boolean logout() throws LoginException
   {
      SecurityAssociationActions.clear();
      return true;
   }
}