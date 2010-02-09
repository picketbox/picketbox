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

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.mapping.MappingManager;

/**
 * <p>
 * Mock security domain. This class is used by the {@code MockSecurityManagement} to obtain the security managers
 * applicable for a domain.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MockSecurityDomain
{
   private final AuthenticationManager authenticationManager;

   private final AuthorizationManager authorizationManager;

   private final MappingManager mappingManager;

   private final AuditManager auditManager;

   private final IdentityTrustManager identityTrustManager;

   /**
    * <p>
    * Creates a {@code MockSecurityDomain} instance with the specified domain name.
    * </p>
    * 
    * @param domainName a {@code String} representing the name of the security domain.
    */
   public MockSecurityDomain(String domainName)
   {
      this.authenticationManager = new MockAuthenticationManager(domainName);
      this.authorizationManager = new MockAuthorizationManager(domainName);
      this.mappingManager = new MockMappingManager(domainName);
      this.auditManager = new MockAuditManager(domainName);
      this.identityTrustManager = new MockIdentityTrustManager(domainName);
   }

   /**
    * <p>
    * Obtains a reference to the {@code AuthenticationManager} used in this domain.
    * </p>
    * 
    * @return the {@code AuthenticationManager} implementation.
    */
   public AuthenticationManager getAuthenticationManager()
   {
      return this.authenticationManager;
   }

   /**
    * <p>
    * Obtains the {@code AuthorizationManager} used in this domain.
    * </p>
    * 
    * @return the {@code AuthorizationManager} implementation.
    */
   public AuthorizationManager getAuthorizationManager()
   {
      return this.authorizationManager;
   }

   /**
    * <p>
    * Obtains the {@code MappingManager} used in this domain.
    * </p>
    * 
    * @return the {@code MappingManager} implementation.
    */
   public MappingManager getMappingManager()
   {
      return this.mappingManager;
   }

   /**
    * <p>
    * Obtains the {@code AuditManager} used in this domain.
    * </p>
    * 
    * @return the {@code AuditManager} implementation.
    */
   public AuditManager getAuditManager()
   {
      return this.auditManager;
   }

   /**
    * <p>
    * Obtains the {@code IdentityTrustManager} used in this domain.
    * </p>
    * 
    * @return the {@code IdentityTrustManager} implementation.
    */
   public IdentityTrustManager getIdentityTrustManager()
   {
      return this.identityTrustManager;
   }
}
