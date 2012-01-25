/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test.authentication.jaspi;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;

import org.jboss.security.auth.container.modules.AbstractServerAuthModule;


/**
 *  Test Server Auth Module that delegates to a login module stack
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 25, 2007 
 *  @version $Revision$
 */
public class TestServerAuthModule extends AbstractServerAuthModule
{ 
   private LoginContext loginContext;
   private String loginContextName = null; 
   
   public TestServerAuthModule(String loginContextName)
   {
      this.loginContextName = loginContextName;
   } 

   @SuppressWarnings("unchecked")
   public void initialize(MessagePolicy messagePolicyReq, MessagePolicy messagePolicyResp, 
         CallbackHandler cbh, Map options) throws AuthException
   {
      this.options = options;
      try
      {
         this.validateJAASConfiguration();
         loginContext = new LoginContext(loginContextName, cbh);
      }
      catch (LoginException e)
      {
         throw new RuntimeException(e.getLocalizedMessage());
      }

   }

   public void cleanSubject(MessageInfo mi, Subject subj) throws AuthException
   { 
      super.cleanSubject(mi, subj);
      if(this.loginContext != null)
         try
         {
            loginContext.logout();
         }
         catch (LoginException e)
         {
            throw new RuntimeException(e.getLocalizedMessage());
         }
   }

   public AuthStatus secureResponse(MessageInfo mi, Subject clientSubject) throws AuthException
   {
      return null;
   } 

   @Override
   protected boolean validate(Subject clientSubject, MessageInfo messageInfo) throws AuthException
   {
      try
      {
         validateJAASConfiguration();
         this.loginContext.login();
      }
      catch (LoginException e)
      {
         throw new AuthException(e.getLocalizedMessage());
      }
      return true;
   } 
   
   private void validateJAASConfiguration()
   {
      //Lets validate the configuration
      Configuration config = Configuration.getConfiguration();
      AppConfigurationEntry[] appConfigEntries = config.getAppConfigurationEntry(loginContextName);
      if(appConfigEntries.length < 0)
        throw new RuntimeException("No entries for " + loginContextName); 
   }
}
