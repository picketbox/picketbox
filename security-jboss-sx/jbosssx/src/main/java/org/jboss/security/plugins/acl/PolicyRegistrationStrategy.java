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
package org.jboss.security.plugins.acl;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.jboss.security.SecurityUtil;
import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.acl.Util;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.Resource;
import org.jboss.util.NotImplementedException;

/**
 * <p>
 * This is a special implementation of {@code ACLPersistenceStrategy} that looks up the ACLs in the
 * {@code PolicyRegistration}. This is used to get hold of the ACLs that have been specified in the
 * {@code jboss-acl-policy.xml} configuration file and registered with the {@code PolicyRegistration} implementation.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class PolicyRegistrationStrategy implements ACLPersistenceStrategy
{

   private final PolicyRegistration registration;

   /**
    * <p>
    * Creates an instance of {@code PolicyRegistrationStrategy}.
    * </p>
    */
   public PolicyRegistrationStrategy()
   {
      // set the policy registration delegate using the JNDI.
      this(SecurityUtil.getPolicyRegistration());
   }

   /**
    * <p>
    * Creates an instance of {@code PolicyRegistrationStrategy} with the specified {@code PolicyRegistration} as a
    * delegate.
    * </p>
    * 
    * @param registration the {@code PolicyRegistration} instance to be used as this strategy's delegate.
    */
   public PolicyRegistrationStrategy(PolicyRegistration registration)
   {
      this.registration = registration;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLPersistenceStrategy#createACL(org.jboss.security.authorization.Resource)
    */
   public ACL createACL(Resource resource)
   {
      // we don't create anything: ACLs are created by parsing an ACL configuration file.
      throw new NotImplementedException("Read-only strategy: ACLs are created through jboss-acl-policy.xml");
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLPersistenceStrategy#createACL(org.jboss.security.authorization.Resource,
    *      java.util.Collection)
    */
   public ACL createACL(Resource resource, Collection<ACLEntry> entries)
   {
      // we don't create anything: ACLs are created by parsing an ACL configuration file.
      throw new NotImplementedException("Read-only strategy: ACLs are created through jboss-acl-policy.xml");
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLPersistenceStrategy#getACL(org.jboss.security.authorization.Resource)
    */
   public ACL getACL(Resource resource)
   {
      String resourceString = Util.getResourceAsString(resource);
      Map<String, Object> context = new HashMap<String, Object>();
      context.put("resource", resourceString);
      return (ACL) this.registration.getPolicy(null, PolicyRegistration.ACL, context);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLPersistenceStrategy#getACLs()
    */
   @SuppressWarnings("unchecked")
   public Collection<ACL> getACLs()
   {
      Map<String, Object> context = new HashMap<String, Object>();
      context.put("resource", "ALL");
      return (Collection<ACL>) this.registration.getPolicy(null, PolicyRegistration.ACL, context);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLPersistenceStrategy#removeACL(org.jboss.security.acl.ACL)
    */
   public boolean removeACL(ACL acl)
   {
      // we don't remove anything: ACLs are removed by undeploying the app that has the configuration file.
      throw new NotImplementedException("Read-only strategy: ACLs are removed upon application undeployment");
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLPersistenceStrategy#removeACL(org.jboss.security.authorization.Resource)
    */
   public boolean removeACL(Resource resource)
   {
      // we don't remove anything: ACLs are removed by undeploying the app that has the configuration file.
      throw new NotImplementedException("Read-only strategy: ACLs are removed upon application undeployment");
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.acl.ACLPersistenceStrategy#updateACL(org.jboss.security.acl.ACL)
    */
   public boolean updateACL(ACL acl)
   {
      throw new NotImplementedException("Unable to update ACL: this is a read-only strategy");
   }

}
