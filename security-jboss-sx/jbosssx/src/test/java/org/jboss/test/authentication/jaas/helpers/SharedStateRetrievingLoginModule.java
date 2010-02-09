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
package org.jboss.test.authentication.jaas.helpers;

import java.security.Principal;
import java.security.acl.Group;

import javax.security.auth.login.LoginException;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

/**
 * Retrieves the username password from options 
 * from the shated state
 * @author Anil.Saldhana@redhat.com
 */
public class SharedStateRetrievingLoginModule
extends AbstractServerLoginModule
{
   private String username = null;

   @SuppressWarnings("unchecked")
   @Override
   public boolean login() throws LoginException
   {
      username = (String) sharedState.get("javax.security.auth.login.name");
      Object cred = sharedState.get("javax.security.auth.login.password");
      
      //Get the ones to verify from options
      String id = (String) options.get("username");
      Object pass = options.get("password");
      
      boolean idmatch = username.equals(id);
      boolean passmatch = false;
      
      if(cred instanceof char[])
      { 
         String a = (String) pass;
         String b = new String((char[])cred);
         passmatch = a.equals(b);
      }
      else
         passmatch = ((String)cred).equals(pass);
      if(!idmatch && passmatch)
         throw new LoginException(username + "=" + id + "::" + cred + "=" + pass);
      super.loginOk = true;
      return super.login();
   }

   @Override
   protected Principal getIdentity()
   {
      return new SimplePrincipal(username);
   }

   @Override
   protected Group[] getRoleSets() throws LoginException
   {
      return null;
   }
}