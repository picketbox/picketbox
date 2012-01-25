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
package org.jboss.test.authorization.web;

import javax.security.auth.Subject;

import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.modules.AuthorizationModuleDelegate;
import org.jboss.security.authorization.resources.WebResource;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;

/**
 * Simple Test AuthorizationDelegate that uses the system property
 * uri=role
 * @author asaldhana 
 */
public class TestWebAuthorizationModuleDelegate extends AuthorizationModuleDelegate
{ 
   public TestWebAuthorizationModuleDelegate()
   {   
   }
   
   @Override
   public int authorize(Resource resource, Subject subject, RoleGroup role)
   {
      WebResource webResource = (WebResource) resource; 
      String requestURI = webResource.getCanonicalRequestURI();

      String roleName = System.getProperty(requestURI);
      if( role.containsRole(new SimpleRole(roleName)))
        return AuthorizationContext.PERMIT; 
      
      return AuthorizationContext.DENY;
   } 
}