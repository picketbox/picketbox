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
package org.jboss.security.acl.config;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.jboss.logging.Logger;
import org.jboss.security.config.ACLInfo;
import org.jboss.xb.binding.GenericValueContainer;

/**
 * <p>
 * A container for creating {@code ACLInfo} objects when an application policy that specifies ACL modules is parsed by
 * JBoss XB.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLInfoContainer implements GenericValueContainer
{
   private static Logger log = Logger.getLogger(ACLInfoContainer.class);

   private final List<ACLProviderEntry> providerEntries = new ArrayList<ACLProviderEntry>();

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#addChild(javax.xml.namespace.QName, java.lang.Object)
    */
   public void addChild(QName name, Object value)
   {
      if (log.isTraceEnabled())
         log.trace("addChild:Qname=" + name + ":value=" + value);

      if (value instanceof ACLProviderEntry)
      {
         ACLProviderEntry entry = (ACLProviderEntry) value;
         this.providerEntries.add(entry);
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#instantiate()
    */
   public Object instantiate()
   {
      ACLInfo info = new ACLInfo("dummy");
      info.add(providerEntries);
      return info;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#getTargetClass()
    */
   public Class<?> getTargetClass()
   {
      return ACLInfo.class;
   }

}
