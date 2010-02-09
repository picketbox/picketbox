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
package org.jboss.security.auth.container.config;

import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.jboss.security.config.ModuleOption;
import org.jboss.xb.binding.GenericValueContainer;

//$Id$

/**
 *  JBXB Container for parsing an AuthModuleEntry (A configuration entry for
 *  JSR-196 Auth Modules that is similar to the JAAS AppConfigurationEntry)
 *  @author <a href="mailto:anil.saldhana@jboss.org>anil.saldhana@jboss.org</a>
 *  @since  Dec 20, 2005 
 */
public class AuthModuleEntryHolder implements GenericValueContainer
{  
   private Map<String,Object> moduleOptions = new HashMap<String,Object>();
   String moduleName = null; 
   String loginModuleStackRefName = null;
   
   public void addChild(QName name, Object value)
   {
      if("code".equals(name.getLocalPart()))
      {
         moduleName = (String)value; 
      }
      else if( "login-module-stack-ref".equals(name.getLocalPart()))
      {
         loginModuleStackRefName = (String)value; 
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
   
   public AuthModuleEntry getEntry()
   {
      return new AuthModuleEntry( moduleName,moduleOptions,loginModuleStackRefName );
   }
   
   public Object instantiate()
   { 
      return new AuthModuleEntry( moduleName,moduleOptions,loginModuleStackRefName );
   }
   
   public Class<?> getTargetClass()
   { 
      return AuthModuleEntry.class;
   }
   
}