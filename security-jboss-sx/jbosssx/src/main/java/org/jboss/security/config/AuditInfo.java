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
package org.jboss.security.config;

import org.jboss.security.audit.config.AuditProviderEntry;

//$Id$

/**
 *  Information on Audit Configuration in the ApplicationPolicy
 *  @author Anil.Saldhana@redhat.com
 *  @since  May 10, 2007 
 *  @version $Revision$
 */
public class AuditInfo extends BaseSecurityInfo<AuditProviderEntry>
{   
   public AuditInfo(String name)
   {
      super(name); 
   }

   public AuditProviderEntry[] getAuditProviderEntry()
   {
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission(GET_CONFIG_ENTRY_PERM); 
      AuditProviderEntry[] entries = new AuditProviderEntry[moduleEntries.size()];
      moduleEntries.toArray(entries);
      return entries;
   }

   @Override
   protected BaseSecurityInfo<AuditProviderEntry> create(String name)
   { 
      return new AuditInfo(name);
   }
}
