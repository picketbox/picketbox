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

import org.jboss.security.audit.AuditEvent;
import org.jboss.security.audit.AuditManager;

/**
 * <p>
 * A mock {@code AuditManager} implementation used in the tests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MockAuditManager implements AuditManager
{

   private final String domainName;

   /**
    * <p>
    * Creates an instance of {@code MockAuditManager} with the specified security domain name.
    * </p>
    * 
    * @param domainName a {@code String} representing the name of the security domain.
    */
   public MockAuditManager(String domainName)
   {
      this.domainName = domainName;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.audit.AuditManager#audit(org.jboss.security.audit.AuditEvent)
    */
   public void audit(AuditEvent event)
   {
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
