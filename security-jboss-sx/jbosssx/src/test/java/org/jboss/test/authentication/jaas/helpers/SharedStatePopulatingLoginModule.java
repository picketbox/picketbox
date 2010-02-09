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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;

/**
 * Places the username password from options 
 * onto the shated state
 * @author Anil.Saldhana@redhat.com
 */
public class SharedStatePopulatingLoginModule
extends UsernamePasswordLoginModule
{
   private String username = null;

   @SuppressWarnings("unchecked")
   @Override
   public boolean login() throws LoginException
   {
      NameCallback nc = new NameCallback("User name: ", "guest");
      PasswordCallback pc = new PasswordCallback("Password: ", false);
      Callback[] callbacks = {nc, pc};
      try
      {
         this.callbackHandler.handle(callbacks);
      }
      catch (Exception e)
      {
         throw new LoginException(e.getLocalizedMessage());
      }
      
      username = nc.getName();
      Object cred = pc.getPassword();
      if(username == null)
         throw new LoginException("No username");
      this.sharedState.put("javax.security.auth.login.name", username);
      this.sharedState.put("javax.security.auth.login.password", cred);
      super.loginOk = true;
      return true;
   }

   @Override
   protected Principal getIdentity()
   {
      return new SimplePrincipal(username);
   }

   @Override
   protected Group[] getRoleSets()
   {
      SimpleGroup roles = new SimpleGroup("Roles");
      Group[] roleSets = {roles};
      roles.addMember(new SimplePrincipal("TestRole"));
      roles.addMember(new SimplePrincipal("Role2"));
      return roleSets;
   }

   @Override
   protected String getUsersPassword() throws LoginException
   {
      return (String) this.options.get("password");
   }
}