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

import java.util.HashSet;
import java.util.Set;

import org.jboss.logging.Logger;
import org.jboss.security.acl.ACLEntry;

/**
 * <p>
 * A container for holding the contents parsed from a {@code <acl-definition>} section of {@code jboss-acl.xml}.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @since Jan 21, 2010
 */
public class ACLBaseDefinition
{
   protected static Logger logger = Logger.getLogger(ACLBaseDefinition.class);

   protected String resource;

   protected String baseResource;

   protected final Set<ACLEntry> entries = new HashSet<ACLEntry>();

   /**
    * <p>
    * Adds a parsed {@code ACLEntry} to the list of entries of this {@code ACLDefinition}.
    * </p>
    * 
    * @param entry the {@code ACLEntry} to be added.
    */
   public void addACLEntry(Object entry)
   {
      logger.debug("addEntry: " + entry);

      if (entry instanceof ACLEntry)
         this.entries.add((ACLEntry) entry);
   }

   /**
    * <p>
    * Obtains the configured {@code <acl-definition>} resource.
    * </p>
    * 
    * @return a {@code String} containing the resource as configured in the XML file.
    */
   public String getResource()
   {
      return resource;
   }

   /**
    * <p>
    * Obtains the configured {@code <acl-definition>} base-resource, as per the {@code extends} attribute in the XML
    * file.
    * </p>
    * 
    * @return a {@code String} containing the base-resource as configured in the XML file, or {@code null} if no base
    *         resource is available.
    */
   public String getBaseResource()
   {
      return baseResource;
   }

   /**
    * <p>
    * Obtains the ACL entries that have been configured in this ACL definition.
    * </p>
    * 
    * @return a {@code List<ACLEntry>} containing the configured entries.
    */
   public Set<ACLEntry> getEntries()
   {
      return entries;
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
         ACLBaseDefinition other = (ACLBaseDefinition) obj;
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