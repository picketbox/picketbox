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
package org.picketbox.test.pojos;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLImpl;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.authorization.Resource;

/**
 * <p>
 * This class implements an {@code ACLPersistenceStrategy} that maintains the ACLs in memory.
 * NOTE: this class is not thread safe and should be used solely for testing purposes.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MemoryOnlyACLStrategy implements ACLPersistenceStrategy
{
   
   private static final Map<Resource, ACL> acls = new HashMap<Resource, ACL>();
   
   /*
    * (non-Javadoc)
    * @see org.jboss.security.acl.ACLPersistenceStrategy#createACL(org.jboss.security.authorization.Resource)
    */
   public ACL createACL(Resource resource)
   {
      ACL acl = new ACLImpl(resource);
      acls.put(resource, acl);
      return acl;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.acl.ACLPersistenceStrategy#createACL(org.jboss.security.authorization.Resource, java.util.Collection)
    */
   public ACL createACL(Resource resource, Collection<ACLEntry> entries)
   {
      ACL acl = new ACLImpl(resource.toString(), entries);
      acls.put(resource, acl);
      return acl;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.acl.ACLPersistenceStrategy#getACL(org.jboss.security.authorization.Resource)
    */
   public ACL getACL(Resource resource)
   {
      return acls.get(resource);
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.acl.ACLPersistenceStrategy#getACLs()
    */
   public Collection<ACL> getACLs()
   {
      return acls.values();
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.acl.ACLPersistenceStrategy#removeACL(org.jboss.security.acl.ACL)
    */
   public boolean removeACL(ACL acl)
   {
      return this.removeACL(acl.getResource());
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.acl.ACLPersistenceStrategy#removeACL(org.jboss.security.authorization.Resource)
    */
   public boolean removeACL(Resource resource)
   {
      ACL removedACL = acls.remove(resource);
      return removedACL != null;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.acl.ACLPersistenceStrategy#updateACL(org.jboss.security.acl.ACL)
    */
   public boolean updateACL(ACL acl)
   {
      ACL updatedACL = acls.put(acl.getResource(), acl);
      return updatedACL != null;
   }
}
