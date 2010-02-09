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

import org.jboss.security.acl.config.ACLProviderEntry;
import org.jboss.security.config.ACLInfo;
import org.jboss.security.config.ControlFlag;

/**
 * <p>
 * This class represents an authorization policy.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLPolicyBean extends BasePolicyBean<FlaggedPolicyModule, ACLInfo>
{

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.BasePolicyBean#getPolicyInfo(java.lang.String)
    */
   @Override
   public ACLInfo getPolicyInfo(String domainName)
   {
      ACLInfo info = new ACLInfo(domainName);
      for (FlaggedPolicyModule module : super.modules)
      {
         ACLProviderEntry entry = new ACLProviderEntry(module.getCode(), module.getOptions());
         entry.setControlFlag(ControlFlag.valueOf(module.getFlag()));
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
      StringBuffer buffer = new StringBuffer("ACL Policy:\n");
      for (int i = 0; i < super.modules.size(); i++)
      {
         FlaggedPolicyModule module = super.modules.get(i);
         buffer.append("Module[" + i + "]\n");
         buffer.append(module.toString());
      }
      return buffer.toString();
   }
}
