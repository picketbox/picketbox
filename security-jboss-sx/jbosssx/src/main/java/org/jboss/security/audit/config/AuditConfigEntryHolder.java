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
package org.jboss.security.audit.config;

import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.jboss.security.config.ModuleOption;
import org.jboss.xb.binding.GenericValueContainer;

//$Id$

/**
 *  A container for creating AuditConfigEntry during jbxb parse
 *  @author Anil.Saldhana@redhat.com
 *  @since  Aug 14, 2007 
 *  @version $Revision$
 */
public class AuditConfigEntryHolder implements GenericValueContainer
{
   private Map<String,Object> moduleOptions = new HashMap<String,Object>();
   String moduleName = null; 
   
   public void addChild(QName name, Object value)
   {
      if("code".equals(name.getLocalPart()))
      {
         moduleName = (String)value; 
      } 
      if(value instanceof ModuleOption)
      {
         ModuleOption mo = (ModuleOption)value;
         moduleOptions.put(mo.getName(),mo.getValue());
      }  
   }

   public void addOption(ModuleOption option)
   {
      moduleOptions.put(option.getName(), option.getValue());
   }
   
   public AuditProviderEntry getEntry()
   { 
      return (AuditProviderEntry)instantiate();
   }
   
   public Object instantiate()
   { 
      AuditProviderEntry entry = new AuditProviderEntry( moduleName,moduleOptions ); 
      return entry;
   }
   
   public Class<?> getTargetClass()
   { 
      return AuditProviderEntry.class;
   } 
}