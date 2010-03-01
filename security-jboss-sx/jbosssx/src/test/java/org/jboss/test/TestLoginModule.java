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
package org.jboss.test;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jboss.security.SimplePrincipal;

public class TestLoginModule implements LoginModule
{
   Subject subject;
   String principal;
   String name;
   boolean succeed;
   boolean throwEx;

   public TestLoginModule()
   {
   }

   @SuppressWarnings("unchecked")
   public void initialize(Subject subject, CallbackHandler handler, Map sharedState, Map options)
   {
      this.subject = subject;
      principal = (String) options.get("principal");
      if( principal == null )
          principal = "guest";
      name = (String) options.get("name");
      String opt = (String) options.get("succeed");
      succeed = Boolean.valueOf(opt).booleanValue();
      opt = (String) options.get("throwEx");
      throwEx = Boolean.valueOf(opt).booleanValue();
      System.out.println("initialize, name="+name);
      opt = (String) options.get("initEx");
      if( Boolean.valueOf(opt) == Boolean.TRUE )
         throw new IllegalArgumentException("Failed during init, name="+name);
   }

   public boolean login() throws LoginException
   {
      System.out.println("login, name="+name+", succeed="+succeed);
      if( throwEx )
         throw new LoginException("Failed during login, name="+name);
      return succeed;
   }

   public boolean commit() throws LoginException
   {
      System.out.println("commit, name="+name);
      subject.getPrincipals().add(new SimplePrincipal(principal));
      subject.getPublicCredentials().add("A public credential");
      subject.getPrivateCredentials().add("A private credential");
      return true;
   }

   public boolean abort() throws LoginException
   {
      System.out.println("abort, name="+name);
      return true;
   }

   public boolean logout() throws LoginException
   {
      System.out.println("logout, name="+name);
      subject.getPrincipals().remove(new SimplePrincipal(principal));
      return succeed;
   }

}
