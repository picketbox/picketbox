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

import javax.security.auth.login.AppConfigurationEntry;
import javax.xml.namespace.QName;

import org.jboss.xb.binding.GenericValueContainer;

//$Id$

/**
 *  A container for creating LoginModuleStack during jbxb parse.
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Dec 24, 2005 
 *  @version $Revision$
 */
@SuppressWarnings("unchecked")
public class LoginModuleStackContainer implements GenericValueContainer
{
   String lmsName = null;
   
   private ArrayList appEntries = new ArrayList();
   
   public void addChild(QName name, Object value)
   {
      if("name".equals(name.getLocalPart()))
      {
         lmsName = (String)value; 
      } 
      if( value  instanceof AppConfigurationEntry)
         appEntries.add(value);
   }

   public Object instantiate()
   {  
      return new LoginModuleStackHolder(lmsName, appEntries);
   }

   public Class getTargetClass()
   { 
      return LoginModuleStackHolder.class;
   }

}
