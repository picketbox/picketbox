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
package org.jboss.test.security.microcontainer.metadata.support;

import java.util.HashMap;
import java.util.Map;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.ISecurityManagement;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.mapping.MappingManager;

/**
 * <p>
 * A mock {@code ISecurityManagement} implementation used in the tests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MockSecurityManagement implements ISecurityManagement
{

   private static final long serialVersionUID = 5675440537362912806L;

   private static Map<String, MockSecurityDomain> domains = new HashMap<String, MockSecurityDomain>();

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.ISecurityManagement#getAuditManager(java.lang.String)
    */
   public AuditManager getAuditManager(String securityDomain)
   {
      MockSecurityDomain mockDomain = domains.get(securityDomain);
      if (mockDomain == null)
      {
         mockDomain = new MockSecurityDomain(securityDomain);
         domains.put(securityDomain, mockDomain);
      }
      return mockDomain.getAuditManager();
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.ISecurityManagement#getAuthenticationManager(java.lang.String)
    */
   public AuthenticationManager getAuthenticationManager(String securityDomain)
   {
      MockSecurityDomain mockDomain = domains.get(securityDomain);
      if (mockDomain == null)
      {
         mockDomain = new MockSecurityDomain(securityDomain);
         domains.put(securityDomain, mockDomain);
      }
      return mockDomain.getAuthenticationManager();
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.ISecurityManagement#getAuthorizationManager(java.lang.String)
    */
   public AuthorizationManager getAuthorizationManager(String securityDomain)
   {
      MockSecurityDomain mockDomain = domains.get(securityDomain);
      if (mockDomain == null)
      {
         mockDomain = new MockSecurityDomain(securityDomain);
         domains.put(securityDomain, mockDomain);
      }
      return mockDomain.getAuthorizationManager();
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.ISecurityManagement#getIdentityTrustManager(java.lang.String)
    */
   public IdentityTrustManager getIdentityTrustManager(String securityDomain)
   {
      MockSecurityDomain mockDomain = domains.get(securityDomain);
      if (mockDomain == null)
      {
         mockDomain = new MockSecurityDomain(securityDomain);
         domains.put(securityDomain, mockDomain);
      }
      return mockDomain.getIdentityTrustManager();
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.ISecurityManagement#getMappingManager(java.lang.String)
    */
   public MappingManager getMappingManager(String securityDomain)
   {
      MockSecurityDomain mockDomain = domains.get(securityDomain);
      if (mockDomain == null)
      {
         mockDomain = new MockSecurityDomain(securityDomain);
         domains.put(securityDomain, mockDomain);
      }
      return mockDomain.getMappingManager();
   }

}
