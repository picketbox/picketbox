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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLImpl;

/**
 * <p>
 * The {@code ACLConfiguration} class contains all ACL definitions that have been specified in an XML file according to
 * the {@code jboss-acl-configuration} schema. Each definition is used to construct an {@code ACL} instance that will
 * protect the specified resource according to the permissions that are assigned to each identity.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLConfiguration
{

   /** the set of ACL definitions keyed by their resource identifier. */
   private final Map<String, ACLBaseDefinition> definitions = new HashMap<String, ACLBaseDefinition>();

   /**
    * <p>
    * Adds a parsed {@code ACLDefinition} object to the map of definitions.
    * </p>
    * 
    * @param definition the {@code ACLDefinition} instance to be added.
    */
   public void addDefinition(Object definition)
   {
      if (definition instanceof ACLBaseDefinition)
      {
         ACLBaseDefinition aclDefinition = (ACLBaseDefinition) definition;
         this.definitions.put(aclDefinition.getResource(), aclDefinition);
      }
   }

   /**
    * <p>
    * Creates and returns the {@code ACL} objects that correspond to the {@code acl-definition}s specified in the XML
    * configuration file.
    * </p>
    * 
    * @return a {@code Set<ACL>} containing the generated {@code ACL}s.
    */
   public Set<ACL> getConfiguredACLs()
   {
      Set<ACL> configuredACLs = new HashSet<ACL>();
      for (ACLBaseDefinition definition : this.definitions.values())
      {
         Set<ACLEntry> entries = this.getEntries(definition, new ArrayList<String>());
         ACLImpl acl = new ACLImpl(definition.getResource(), entries);
         configuredACLs.add(acl);
      }
      return configuredACLs;
   }

   /**
    * <p>
    * This method retrieves the set of {@code ACLEntry} objects that belong to an ACL, recursively getting the entries
    * from the parent definitions when the extension configuration is used. An extending {@code ACLDefinition}
    * "inherits" the entries from its parent and is free to add or override entries as needed.
    * </p>
    * 
    * @param definition the {@code ACLBaseDefinition} that contains the data used to retrieve the entries.
    * @param visitedACLs a {@code List} of the visited ACLs to detect circular dependencies.
    * @return a {@code Set<ACLEntry>} containing the entries that will be used to create an {@code ACL} according to the
    *         specified definition.
    * @throws RuntimeException if a circular dependency is detected among the {@code ACLDefinition} objects.
    */
   private Set<ACLEntry> getEntries(ACLBaseDefinition definition, List<String> visitedACLs)
   {
      if (visitedACLs.contains(definition.getResource()))
         throw new RuntimeException("Circular dependency between ACLs has been detected");

      visitedACLs.add(definition.getResource());
      if (definition.getBaseResource() != null)
      {
         ACLBaseDefinition superDefinition = this.definitions.get(definition.getBaseResource());
         if (superDefinition != null)
         {
            Set<ACLEntry> superEntries = this.getEntries(superDefinition, visitedACLs);
            Set<ACLEntry> entries = definition.getEntries();
            entries.addAll(superEntries);
            return entries;
         }
         else
         {
            throw new RuntimeException("Parent ACL not found: " + definition.getBaseResource());
         }
      }
      else
      {
         return definition.getEntries();
      }
   }
}
