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

import javax.xml.namespace.QName;

import org.jboss.logging.Logger;
import org.jboss.xb.binding.GenericValueContainer;

/**
 * <p>
 * A container for holding the contents parsed from a {@code <acl-definition>} section of {@code jboss-acl.xml}.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLDefinition extends ACLBaseDefinition implements GenericValueContainer
{

   private static Logger logger = Logger.getLogger(ACLDefinition.class); 

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#addChild(javax.xml.namespace.QName, java.lang.Object)
    */
   public void addChild(QName name, Object value)
   {
      logger.debug("addChild: name=" + name + ", value=" + value);

      if ("resource".equals(name.getLocalPart()))
      {
         this.resource = (String) value;
      }
      else if ("extends".equals(name.getLocalPart()))
      {
         this.baseResource = (String) value;
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#instantiate()
    */
   public Object instantiate()
   {
      return this;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#getTargetClass()
    */
   public Class<?> getTargetClass()
   {
      return ACLDefinition.class;
   }   

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#equals(java.lang.Object)
    */
   @Override
   public boolean equals(Object obj)
   {
      if (obj instanceof ACLDefinition)
      {
         ACLDefinition other = (ACLDefinition) obj;
         return this.resource.equals(other.resource);
      }
      return false;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#hashCode()
    */
   @Override
   public int hashCode()
   {
      return this.resource.hashCode();
   }

}
