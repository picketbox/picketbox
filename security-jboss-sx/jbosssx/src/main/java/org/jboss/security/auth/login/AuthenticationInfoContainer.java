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
package org.jboss.security.auth.login;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.xml.namespace.QName;

import org.jboss.logging.Logger;
import org.jboss.security.auth.container.config.AuthModuleEntry;
import org.jboss.xb.binding.GenericValueContainer;

/**
 * A container for creating AuthenticationInfo during jbxb parse.
 * 
 * @author Scott.Stark@jboss.org
 * @author <a href="mailto:anil.saldhana@jboss.org>anil.saldhana@jboss.org</a>
 * @version $Revision$
 */
public class AuthenticationInfoContainer
   implements GenericValueContainer
{
   private static Logger log = Logger.getLogger(AuthenticationInfoContainer.class); 

   BaseAuthenticationInfo info = null;
   
   String authName = null; 
   
   @SuppressWarnings("unchecked")
   List moduleEntries = new ArrayList();
   
   @SuppressWarnings("unchecked")
   Map loginModuleStackMap = new HashMap();
   
   boolean isJASPIAuthentication = false;

   @SuppressWarnings("unchecked")
   public void addChild(QName name, Object value)
   {
      log.debug("addChild::" + name + ":" + value);
      if("name".equals(name.getLocalPart()))
      { 
         authName = (String)value;
      }
      else if( value instanceof AppConfigurationEntryHolder )
      {   
         AppConfigurationEntryHolder ace = (AppConfigurationEntryHolder) value; 
         moduleEntries.add(ace.getEntry());
      }
      else if( value instanceof AppConfigurationEntry )
      {  
         AppConfigurationEntry ace = (AppConfigurationEntry) value; 
         moduleEntries.add(ace);
      } 
      else if( value instanceof AuthModuleEntry )
      {
         AuthModuleEntry ame = (AuthModuleEntry)value;
         //Check if the authmodule needs a reference to a loginmodulestack
         String lmshName = ame.getLoginModuleStackHolderName();
         if( lmshName != null )
            ame.setLoginModuleStackHolder((LoginModuleStackHolder)loginModuleStackMap.get(lmshName));
         moduleEntries.add(ame);
         this.isJASPIAuthentication = true;
      }
      else if( value instanceof LoginModuleStackHolder )
      {
         LoginModuleStackHolder lmsh = (LoginModuleStackHolder)value;
         loginModuleStackMap.put( lmsh.getName(), lmsh );
      }
   } 

   @SuppressWarnings("unchecked")
   public Object instantiate()
   { 
      if(isJASPIAuthentication == false)
      {
         info = new AuthenticationInfo(authName);
      }
      else
      {
         info = new JASPIAuthenticationInfo(authName);  
      }

      info.add(moduleEntries);
      return info;
   }

   public Class<?> getTargetClass()
   {
      return BaseAuthenticationInfo.class;
   }

}