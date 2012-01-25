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

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.SecurityContext;
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;

/**
 * Authentication Unit Tests
 * <a href="mailto:anil.saldhana@redhat.com>Anil Saldhana</a>
 * @since May 30, 2008
 */
public class AuthenticationUnitTestCase extends TestCase
{
   private final String securityDomainName = "test";
   
   public void testValidAuthentication() throws Exception
   { 
      SecurityFactory.prepare();
      try
      { 
         String configFile = "config/authentication.conf";
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(am);

         Subject subject = new Subject();
         Principal principal = getPrincipal("anil");
         Object credential = new String("pass");

         boolean result = am.isValid(principal, credential); 
         assertTrue("Valid Auth", result);
         result = am.isValid(principal, credential, subject);
         assertTrue("Valid Auth", result);
         assertTrue("Subject has principals", subject.getPrincipals().size() > 0); 
      }
      finally
      {
         SecurityFactory.release();
      }
   }
   
   public void testInvalidAuthentication() throws Exception
   {
      SecurityFactory.prepare();
      try
      {
         String configFile = "config/authentication.conf";
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(am);

         Principal principal = getPrincipal("anil");
         Object credential = new String("BADGUY");

         boolean result = am.isValid(principal, credential); 
         assertFalse("Valid Auth", result);
      }
      finally
      {
         SecurityFactory.release();
      }
   }
   
   public void testAuthenticationUsingSecurityContext() throws Exception
   {
      SecurityFactory.prepare();
      try
      { 
         String configFile = "config/authentication.conf";
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);
         
         SecurityContext securityContext = SecurityFactory.establishSecurityContext(securityDomainName); 
         
         AuthenticationManager am = securityContext.getAuthenticationManager(); 
         assertNotNull(am);

         Subject subject = new Subject();
         Principal principal = getPrincipal("anil");
         Object credential = new String("pass");
         
         boolean result = am.isValid(principal, credential); 
         assertTrue("Valid Auth", result);
         result = am.isValid(principal, credential, subject);
         assertTrue("Valid Auth", result);
         assertTrue("Subject has principals", subject.getPrincipals().size() > 0); 
         
         securityContext.getUtil().createSubjectInfo(principal, credential, subject);
         assertEquals("UserName == anil", "anil", securityContext.getUtil().getUserName());
         assertEquals("subject is equal", subject, securityContext.getUtil().getSubject());
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
}