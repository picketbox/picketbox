/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2006, Red Hat Middleware LLC, and individual contributors
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
package org.picketbox.test.api;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType; 
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;

/**
 * Authorization Unit Tests
 * <a href="mailto:anil.saldhana@redhat.com>Anil Saldhana</a>
 * @since May 31, 2008
 */
public class AuthorizationUnitTestCase extends TestCase
{
   private final String securityDomainName = "test";
   private final String configFile = "config/authorization.conf";
   
   public void testValidAuthorization() throws Exception
   { 
      SecurityFactory.prepare();
      try
      {
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(am);

         Subject subject = new Subject();
         Principal principal = getPrincipal("anil");
         Object credential = new String("pass");

         boolean result = am.isValid(principal, credential, subject);
         assertTrue("Valid Auth", result);
         assertTrue("Subject has principals", subject.getPrincipals().size() > 0);

         AuthorizationManager authzM = SecurityFactory.getAuthorizationManager(securityDomainName);
         assertNotNull(authzM);
         Resource resource = getResource();
         int decision = authzM.authorize(resource, subject);
         assertTrue(decision == AuthorizationContext.PERMIT);
      }
      finally
      {
         SecurityFactory.release();
      }
   }
   
   public void testInvalidAuthorization() throws Exception
   {
      SecurityFactory.prepare();
      try
      {
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(am);

         Subject subject = new Subject();
         Principal principal = getPrincipal("anil");
         Object credential = new String("pass");

         boolean result = am.isValid(principal, credential, subject);
         assertTrue("Valid Auth", result);
         assertTrue("Subject has principals", subject.getPrincipals().size() > 0);

         AuthorizationManager authzM = SecurityFactory.getAuthorizationManager(securityDomainName);
         assertNotNull(authzM);
         Resource resource = getResource();
         int decision = authzM.authorize(resource, subject);
         assertTrue(decision == AuthorizationContext.PERMIT);
      }
      finally
      {
         SecurityFactory.release();
      }
   }
   
   private Principal getPrincipal(final String name)
   {
      return new Principal()
      {
         public String getName()
         {
            return name;
         }
      };
   }
   
   private Resource getResource()
   {
      return new Resource()
      {
       public ResourceType getLayer()
       {
          return ResourceType.POJO;
       }

       public Map<String, Object> getMap()
       {
          return new HashMap<String,Object>();
       }
      };
   }
}