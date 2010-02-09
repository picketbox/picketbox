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
package org.jboss.security.authorization.config;

import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.jboss.security.config.ControlFlag;
import org.jboss.security.config.ModuleOption;
import org.jboss.xb.binding.GenericValueContainer;

//$Id$

/**
 *  A container for creating AuthorizationConfigurationEntry during jbxb parse.
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Jun 9, 2006 
 *  @version $Revision$
 */
public class AuthorizationConfigEntryHolder implements GenericValueContainer
{
   private Map<String,Object> moduleOptions = new HashMap<String,Object>();
   String moduleName = null;  
   ControlFlag controlFlag = ControlFlag.REQUIRED;
   
   public void addChild(QName name, Object value)
   {
      if("code".equals(name.getLocalPart()))
      {
         moduleName = (String)value; 
      }
      if("flag".equals(name.getLocalPart()))
      {
         String tempVal = (String)value;
         if("optional".equals(tempVal))
            controlFlag = ControlFlag.OPTIONAL;
         else
            if("requisite".equals(tempVal))
               controlFlag = ControlFlag.REQUISITE;
            else
               if("sufficient".equals(tempVal))
                  controlFlag = ControlFlag.SUFFICIENT;
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
   
   public AuthorizationModuleEntry getEntry()
   { 
      return (AuthorizationModuleEntry)instantiate();
   }
   
   public Object instantiate()
   { 
      AuthorizationModuleEntry entry = new AuthorizationModuleEntry( moduleName,moduleOptions );
      entry.setControlFlag(controlFlag);
      return entry;
   }
   
   public Class<?> getTargetClass()
   { 
      return AuthorizationModuleEntry.class;
   }
   
}