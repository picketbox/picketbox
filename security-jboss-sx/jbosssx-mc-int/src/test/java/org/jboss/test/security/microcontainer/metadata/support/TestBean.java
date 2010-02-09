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
 * A simple POJO used in the injection tests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class TestBean
{

   private AuthenticationManager authenticationManager;

   private AuthorizationManager authorizationManager;

   private MappingManager mappingManager;

   private AuditManager auditManager;

   private IdentityTrustManager identityTrustManager;

   /**
    * <p>
    * Obtains the {@code AuthenticationManager} that has been injected into this bean.
    * </p>
    * 
    * @return a reference to the {@code AuthenticationManager}.
    */
   public AuthenticationManager getAuthenticationManager()
   {
      return this.authenticationManager;
   }

   /**
    * <p>
    * Sets the {@code AuthenticationManager}. This is done via injection in the tests.
    * </p>
    * 
    * @param authenticationManager a reference to the {@code AuthenticationManager} to be set.
    */
   public void setAuthenticationManager(AuthenticationManager authenticationManager)
   {
      this.authenticationManager = authenticationManager;
   }

   /**
    * <p>
    * Obtains the {@code AuthorizationManager} that has been injected into this bean.
    * </p>
    * 
    * @return a reference to the {@code AuthorizationManager}.
    */
   public AuthorizationManager getAuthorizationManager()
   {
      return this.authorizationManager;
   }

   /**
    * <p>
    * Sets the {@code AuthorizationManager}. This is done via injection in the tests.
    * </p>
    * 
    * @param authorizationManager a reference to the {@code AuthorizationManager} to be set.
    */
   public void setAuthorizationManager(AuthorizationManager authorizationManager)
   {
      this.authorizationManager = authorizationManager;
   }

   /**
    * <p>
    * Obtains the {@code MappingManager} that has been injected into this bean.
    * </p>
    * 
    * @return a reference to the {@code MappingManager}.
    */
   public MappingManager getMappingManager()
   {
      return this.mappingManager;
   }

   /**
    * <p>
    * Sets the {@code MappingManager}. This is done via injection in the tests.
    * </p>
    * 
    * @param mappingManager a reference to the {@code MappingManager} to be set.
    */
   public void setMappingManager(MappingManager mappingManager)
   {
      this.mappingManager = mappingManager;
   }

   /**
    * <p>
    * Obtains the {@code AuditManager} that has been injected into this bean.
    * </p>
    * 
    * @return a reference to the {@code AuditManager}.
    */
   public AuditManager getAuditManager()
   {
      return this.auditManager;
   }

   /**
    * <p>
    * Sets the {@code AuditManager}. This is done via injection in the tests.
    * </p>
    * 
    * @param auditManager a reference to the {@code AuditManager} to be set.
    */
   public void setAuditManager(AuditManager auditManager)
   {
      this.auditManager = auditManager;
   }

   /**
    * <p>
    * Obtains the {@code IdentityTrustManager} that has been injected into this bean.
    * </p>
    * 
    * @return a reference to the {@code IdentityTrustManager}.
    */
   public IdentityTrustManager getIdentityTrustManager()
   {
      return this.identityTrustManager;
   }

   /**
    * <p>
    * Sets the {@code IdentityTrustManager}. This is done via injection in the tests.
    * </p>
    * 
    * @param identityTrustManager a reference to the {@code IdentityTrustManager} to be set.
    */
   public void setIdentityTrustManager(IdentityTrustManager identityTrustManager)
   {
      this.identityTrustManager = identityTrustManager;
   }

}
