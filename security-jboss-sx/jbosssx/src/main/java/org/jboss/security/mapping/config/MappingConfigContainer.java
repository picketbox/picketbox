/*
 * JBoss, Home of Professional Open Source
 * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.security.mapping.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.jboss.logging.Logger;
import org.jboss.security.config.MappingInfo;
import org.jboss.xb.binding.GenericValueContainer;

// $Id: RoleMappingConfigContainer.java 45942 2006-06-28 02:14:46Z asaldhana $

/**
 * A container for creating RoleMappingConfig during jbxb parse.
 * 
 * @author Anil.Saldhana@jboss.org
 * @version $Revision: 45942 $
 */
public class MappingConfigContainer implements GenericValueContainer
{
   private static Logger MappingConfigContainer = Logger.getLogger(MappingConfigContainer.class);

   private final Map<String, List<MappingModuleEntry>> moduleEntries = new HashMap<String, List<MappingModuleEntry>>();

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#addChild(javax.xml.namespace.QName, java.lang.Object)
    */
   public void addChild(QName name, Object value)
   {
      if (MappingConfigContainer.isTraceEnabled())
         MappingConfigContainer.trace("addChild:Qname=" + name + ":value=" + value);
      if (value instanceof MappingModuleEntry)
      {
         MappingModuleEntry mme = (MappingModuleEntry) value;
         String type = mme.getMappingModuleType();
         // organize the mapping modules in groups according to their type.
         if (this.moduleEntries.containsKey(type))
         {
            this.moduleEntries.get(type).add(mme);
         }
         else
         {
            List<MappingModuleEntry> entries = new ArrayList<MappingModuleEntry>();
            entries.add(mme);
            this.moduleEntries.put(type, entries);
         }
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#instantiate()
    */
   public Object instantiate()
   {
      Map<String, MappingInfo> infos = new HashMap<String, MappingInfo>();

      // create a MappingInfo instance of each group of mapping modules.
      for (String type : this.moduleEntries.keySet())
      {
         // application policy name will be reset in ApplicationPolicyContainer.
         MappingInfo mapping = new MappingInfo("dummy");
         mapping.add(this.moduleEntries.get(type));
         infos.put(type, mapping);
      }
      return infos;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.xb.binding.GenericValueContainer#getTargetClass()
    */
   public Class<?> getTargetClass()
   {
      return MappingInfo.class;
   }
}
