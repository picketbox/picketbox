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
import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLEntryImpl;
import org.jboss.security.acl.BasicACLPermission;
import org.jboss.security.acl.CompositeACLPermission;
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.plugins.IdentityFactory;
import org.jboss.xb.binding.GenericValueContainer;

/**
 * <p>
 * A container for creating {@code ACLEntry} objects when a jboss-acl configuration is parsed by JBoss XB.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLEntryHolder implements GenericValueContainer
{

   private static Logger logger = Logger.getLogger(ACLEntryHolder.class);

   private Identity identity;

   private CompositeACLPermission permission;

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#addChild(javax.xml.namespace.QName, java.lang.Object)
    */
   public void addChild(QName name, Object value)
   {
      logger.debug("addChild: name=" + name + ", value=" + value);

      if ("identity-name".equals(name.getLocalPart()))
      {
         String identityName = (String) value;
         this.identity = this.getIdentityFromString(identityName);
      }
      else if ("permissions".equals(name.getLocalPart()))
      {
         String permissions = (String) value;
         this.permission = this.getPermissionsFromString(permissions);
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#instantiate()
    */
   public Object instantiate()
   {
      return new ACLEntryImpl(this.permission, this.identity);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#getTargetClass()
    */
   public Class<?> getTargetClass()
   {
      return ACLEntry.class;
   }

   /**
    * <p>
    * Creates an {@code Identity} object from the specified {@code identityName} parameter.
    * </p>
    * 
    * @param identityName a {@code String} that represents the identity to be built.
    * @return the constructed {@code Identity} instance, or {@code null} if the {@code Identity} object cannot be built.
    */
   private Identity getIdentityFromString(String identityName)
   {
      try
      {
         return IdentityFactory.createIdentity(identityName);
      }
      catch (Exception e)
      {
         logger.debug("Exception caught while constructing Identity object", e);
         return null;
      }
   }

   /**
    * <p>
    * Creates a {@code CompositeACLPermission} from the specified {@code permissionString} parameter.
    * </p>
    * 
    * @param permissionString a {@code String} containing the permissions assigned to the identity, separated by a comma
    *            (e.g. {@code CREATE,READ,UPDATE}).
    * @return the constructed {@code CompositeACLPermission} object.
    */
   private CompositeACLPermission getPermissionsFromString(String permissionString)
   {
      List<BasicACLPermission> permissions = new ArrayList<BasicACLPermission>();
      if (permissionString != null)
      {
         // extract each permission from the permission string.
         String[] elements = permissionString.split(",");
         for (String element : elements)
         {
            try
            {
               permissions.add(BasicACLPermission.valueOf(element));
            }
            catch (RuntimeException re)
            {
               logger.debug("No BasicACLPermission named " + element + " found", re);
            }
         }
      }

      return new CompositeACLPermission(permissions.toArray(new BasicACLPermission[permissions.size()]));
   }
}
