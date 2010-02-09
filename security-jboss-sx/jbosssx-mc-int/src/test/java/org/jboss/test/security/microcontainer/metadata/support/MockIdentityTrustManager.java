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

import org.jboss.security.SecurityContext;
import org.jboss.security.identitytrust.IdentityTrustManager;

/**
 * <p>
 * A mock {@code IdentityTrustManager} implementation used in the tests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MockIdentityTrustManager implements IdentityTrustManager
{

   private final String domainName;

   /**
    * <p>
    * Creates an instance of {@code MockIdentityTrustManager} with the specified security domain name.
    * </p>
    * 
    * @param domainName a {@code String} representing the name of the security domain.
    */
   public MockIdentityTrustManager(String domainName)
   {
      this.domainName = domainName;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.identitytrust.IdentityTrustManager#isTrusted(org.jboss.security.SecurityContext)
    */
   public TrustDecision isTrusted(SecurityContext context)
   {
      return null;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.BaseSecurityManager#getSecurityDomain()
    */
   public String getSecurityDomain()
   {
      return this.domainName;
   }

}
