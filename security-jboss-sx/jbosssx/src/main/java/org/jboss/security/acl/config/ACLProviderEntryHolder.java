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

import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.jboss.security.config.ControlFlag;
import org.jboss.security.config.ModuleOption;
import org.jboss.xb.binding.GenericValueContainer;

/**
 * <p>
 * A container for creating {@code ACLProviderEntry} objects when an application policy that specifies ACL modules is
 * parsed by JBoss XB.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLProviderEntryHolder implements GenericValueContainer
{
   private String moduleName = null;

   private ControlFlag controlFlag = ControlFlag.REQUIRED;

   private final Map<String, Object> moduleOptions = new HashMap<String, Object>();

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#addChild(javax.xml.namespace.QName, java.lang.Object)
    */
   public void addChild(QName name, Object value)
   {
      // the fully-qualified class name of the ACLProvider.
      if ("code".equals(name.getLocalPart()))
      {
         this.moduleName = (String) value;
      }
      // the control flag.
      if ("flag".equals(name.getLocalPart()))
      {
         String flag = (String) value;
         if ("optional".equals(flag))
            this.controlFlag = ControlFlag.OPTIONAL;
         else if ("requisite".equals(flag))
            this.controlFlag = ControlFlag.REQUISITE;
         else if ("sufficient".equals(flag))
            this.controlFlag = ControlFlag.SUFFICIENT;
      }
      // the options of the ACLProvider.
      if (value instanceof ModuleOption)
      {
         ModuleOption option = (ModuleOption) value;
         this.moduleOptions.put(option.getName(), option.getValue());
      }
   }

   /**
    * <p>
    * Adds the specified option to the set of options used by the {@code ACLProvider}.
    * </p>
    * 
    * @param option a {@code ModuleOption} instance representing the option to be added.
    */
   public void addOption(ModuleOption option)
   {
      moduleOptions.put(option.getName(), option.getValue());
   }

   /**
    * <p>
    * Constructs and returns an {@code ACLProviderEntry} with the information contained in this class.
    * </p>
    * 
    * @return a reference to the constructed {@code ACLProviderEntry} object.
    */
   public ACLProviderEntry getEntry()
   {
      return (ACLProviderEntry) instantiate();
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#instantiate()
    */
   public Object instantiate()
   {
      ACLProviderEntry entry = new ACLProviderEntry(this.moduleName, this.moduleOptions);
      entry.setControlFlag(this.controlFlag);
      return entry;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#getTargetClass()
    */
   public Class<?> getTargetClass()
   {
      return ACLProviderEntry.class;
   }
}
