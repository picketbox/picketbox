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
package org.jboss.security.authorization;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.jboss.logging.Logger;
import org.jboss.security.authorization.config.AuthorizationConfigEntryHolder;
import org.jboss.security.authorization.config.AuthorizationModuleEntry;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.xb.binding.GenericValueContainer;

//$Id$

/**
 * A container for creating AuthorizationInfo during jbxb parse.
 *  
 * @author anil.saldhana@jboss.org
 * @version $Revision$
 */
public class AuthorizationInfoContainer
   implements GenericValueContainer
{
   private static Logger log = Logger.getLogger(AuthorizationInfoContainer.class); 

   AuthorizationInfo info = null;
   
   String authName = null; 
   
   List<AuthorizationModuleEntry> moduleEntries = new ArrayList<AuthorizationModuleEntry>(); 

   public void addChild(QName name, Object value)
   {
      log.debug("addChild::" + name + ":" + value);
      if("name".equals(name.getLocalPart()))
      { 
         authName = (String)value;
      }
      else if( value instanceof AuthorizationConfigEntryHolder )
      {   
         AuthorizationConfigEntryHolder ace = (AuthorizationConfigEntryHolder) value; 
         moduleEntries.add(ace.getEntry());
      } 
   } 

   public Object instantiate()
   {  
      info = new AuthorizationInfo(authName);  
      info.add(moduleEntries);
      return info;
   }

   public Class<?> getTargetClass()
   {
      return AuthorizationInfo.class;
   }
}