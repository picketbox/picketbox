/*
 * JBoss, Home of Professional Open Source
 * Copyright 2007, JBoss Inc., and individual contributors as indicated
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
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
package org.jboss.security.acl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.security.authorization.AuthorizationException;
import org.jboss.security.authorization.EntitlementHolder;
import org.jboss.security.authorization.Permission;
import org.jboss.security.authorization.Resource;
import org.jboss.security.config.ControlFlag;
import org.jboss.security.identity.Identity;

/**
 * Represents a set of ACLProviders
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Jan 30, 2008
 * @version $Revision$
 */
public abstract class ACLContext
{
   protected String securityDomainName = null;

   protected Map<String, Object> sharedState = new HashMap<String, Object>();

   protected List<ACLProvider> modules = new ArrayList<ACLProvider>();

   /**
    * Control Flags for the individual modules
    */
   protected List<ControlFlag> controlFlags = new ArrayList<ControlFlag>();

   /**
    * Instance Based Security Get all the entitlements assigned to the components of a Resource
    * 
    * @param clazz class type of the entitlements
    * @param resource A Resource (Can be a Portal Resource, a Rules Resource)
    * @param identity The Identity against whom the entitlements need to be generated
    * @return a Entitlements Wrapper
    * @throws AuthorizationException
    */
   public abstract <T> EntitlementHolder<T> getEntitlements(final Class<T> clazz, final Resource resource,
         final Identity identity) throws AuthorizationException;

   /**
    * <p>
    * Authorize access to the resource if the specified identity has the proper permissions.
    * </p>
    * 
    * @param resource the {@code Resource} being accessed.
    * @param identity the {@code Identity} trying to access the resource.
    * @param permission the permissions required for access to be granted.
    * @return {@code AuthorizationContext#PERMIT} if access has been granted; {@code AuthorizationContext#DENY}
    *         otherwise.
    * @throws AuthorizationException if an error occurs while authorizing access to the resource.
    */
   public abstract int authorize(Resource resource, Identity identity, Permission permission)
         throws AuthorizationException;

   /**
    * Return the Security Domain Name
    * 
    * @return security domain
    */
   public String getSecurityDomain()
   {
      return this.securityDomainName;
   }
}