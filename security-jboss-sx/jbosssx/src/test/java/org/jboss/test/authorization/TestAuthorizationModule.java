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
package org.jboss.test.authorization;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.AuthorizationException;
import org.jboss.security.authorization.AuthorizationModule;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;

//$Id$

/**
 *  Test AuthorizationModule
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jan 3, 2008 
 *  @version $Revision$
 */
public class TestAuthorizationModule implements AuthorizationModule
{ 
   private Subject subject = null; 
   private RoleGroup role = null;
   
   public boolean abort() throws AuthorizationException
   { 
      return true;
   }

   public int authorize(Resource resource)
   {
      if(subject == null)
         return AuthorizationContext.DENY;
      if(resource.getLayer() == ResourceType.WEB)
      {
         if(role != null && role.containsAll(new SimpleRole("ServletUserRole")))
            return AuthorizationContext.PERMIT;
      }
      return AuthorizationContext.DENY;
   }

   public boolean commit() throws AuthorizationException
   {
      return true;
   }

   public boolean destroy()
   {
      return true;
   }

   public void initialize(Subject subject, CallbackHandler handler, 
         Map<String, Object> sharedState,
         Map<String, Object> options,
         RoleGroup role)
   {
      this.subject = subject;
      this.role = role;
   }
}