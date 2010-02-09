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
package org.jboss.security.microcontainer.beans;

import java.util.HashMap;
import java.util.Map;

import org.jboss.security.config.MappingInfo;
import org.jboss.security.mapping.config.MappingModuleEntry;

/**
 * <p>
 * This class represents a mapping policy.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MappingPolicyBean extends BasePolicyBean<MappingPolicyModule, MappingInfo>
{

   /**
    * <p>
    * Groups the mapping modules according to their types, and creates a {@code MappingInfo} object for each group of
    * mapping modules.
    * </p>
    * 
    * @param domainName the name of the application-policy where the mappings where specified.
    * @return a {@code Map<String,MappingInfo>} containing the generated {@code MappingInfo} objects keyed by the type
    *         of their modules.
    */
   public Map<String, MappingInfo> getMappingInfoByType(String domainName)
   {
      // get the mapping info that contains all mapping modules.
      MappingInfo completeInfo = this.getPolicyInfo(domainName);
      // now group the modules by type and create a mapping info for each group.
      Map<String, MappingInfo> result = new HashMap<String, MappingInfo>();
      for (MappingModuleEntry entry : completeInfo.getModuleEntries())
      {
         String type = entry.getMappingModuleType();
         if (result.containsKey(type))
            result.get(type).add(entry);
         else
         {
            MappingInfo info = new MappingInfo(domainName);
            info.add(entry);
            result.put(type, info);
         }
      }
      return result;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.BasePolicyBean#getPolicyInfo(java.lang.String)
    */
   @Override
   public MappingInfo getPolicyInfo(String domainName)
   {
      MappingInfo info = new MappingInfo(domainName);
      for (MappingPolicyModule module : super.modules)
      {
         MappingModuleEntry entry = new MappingModuleEntry(module.getCode(), module.getOptions(), module.getType());
         info.add(entry);
      }
      return info;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#toString()
    */
   @Override
   public String toString()
   {
      StringBuffer buffer = new StringBuffer("Role-Mapping Policy:\n");
      for (int i = 0; i < super.modules.size(); i++)
      {
         MappingPolicyModule module = super.modules.get(i);
         buffer.append("Module[" + i + "]\n");
         buffer.append(module.toString());
      }
      return buffer.toString();
   }
}
