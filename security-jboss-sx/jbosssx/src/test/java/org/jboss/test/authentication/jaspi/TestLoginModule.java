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
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jboss.security.SimplePrincipal;


/**
 *  Test Login Module
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 26, 2007 
 *  @version $Revision$
 */
public class TestLoginModule implements LoginModule
{ 
   private Subject subject;
   private CallbackHandler cbh;
   private Map<String, ?> sharedState;
   private Map<String, ?> options;
   
   private String username = null;

   public boolean abort() throws LoginException
   { 
      return true;
   }

   public boolean commit() throws LoginException
   { 
      subject.getPrincipals().add(new SimplePrincipal(username));
      return true;
   }

   public void initialize(Subject subject, 
         CallbackHandler cbh, 
         Map<String, ?> sharedState, 
         Map<String, ?> options)
   { 
      this.subject = subject;
      this.cbh = cbh;
      this.sharedState = sharedState;
      this.options = options;
   }

   public boolean login() throws LoginException
   { 
      NameCallback nc = new NameCallback("UserName=", "guest");
      PasswordCallback pwd = new PasswordCallback("Password=", false);
      try
      {
         cbh.handle(new Callback[]{nc,pwd});
         username = nc.getName();
         String p = new String(pwd.getPassword());
         if(username.equals(options.get("principal")) && p.equals(options.get("pass")))
            return true;
      }
      catch (Exception e)
      {
         throw new LoginException(e.getLocalizedMessage());
      } 
      return false;
   }

   public boolean logout() throws LoginException
   { 
      subject = null;
      return false;
   } 
}
