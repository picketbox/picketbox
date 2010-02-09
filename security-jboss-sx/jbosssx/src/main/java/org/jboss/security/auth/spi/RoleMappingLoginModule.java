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
package org.jboss.security.auth.spi;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;

import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.jboss.logging.Logger;
import org.jboss.util.StringPropertyReplacer;

//$Id$

/**
 *  JBAS-3323: Role Mapping Login Module that maps application role to 
 *  declarative role
 *  - You will need to provide a properties file name with the option "rolesProperties"
 *    which has the role to be replaced as the key and a comma-separated role names
 *    as replacements.
 *  - This module should be used with the "optional" mode, as it just adds
 *  onto the authenticated subject
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Jun 22, 2006
 *  @version $Revision$
 */
public class RoleMappingLoginModule extends AbstractServerLoginModule
{   
   private static Logger log = Logger.getLogger(RoleMappingLoginModule.class);
   private boolean trace = log.isTraceEnabled(); 
   
   /**
    * Should the matching role be replaced
    */
   protected boolean REPLACE_ROLE = false;
    
   /**
    * @see LoginModule#login()
    */
   public boolean login() throws LoginException
   {
      if( super.login() == true )
         return true;
 
      super.loginOk = true;
      return true;
   } 
   
   /**
    * @see AbstractServerLoginModule#getIdentity() 
    */
   protected Principal getIdentity()
   { 
      //We have an authenticated subject
      Iterator<? extends Principal> iter = subject.getPrincipals().iterator();
      while(iter.hasNext())
      {
         Principal p = iter.next();
         if(p instanceof Group == false)
            return p;
      }
      return null;
   }

   /**
    * @see AbstractServerLoginModule#getRoleSets()
    */
   protected Group[] getRoleSets() throws LoginException
   { 
      String rep = (String)options.get("replaceRole");
      if("true".equalsIgnoreCase(rep))
         this.REPLACE_ROLE = true;
      
      //Get the properties file name from the options
      String propFileName = (String)options.get("rolesProperties");
      if(propFileName == null)
         throw new IllegalStateException("rolesProperties option needs to be provided");
      // Replace any system property references like ${x}
      propFileName = StringPropertyReplacer.replaceProperties(propFileName);
      Group group = getExistingRolesFromSubject();
      if(propFileName != null)
      { 
         Properties props = new Properties();
         try
         { 
            props = Util.loadProperties(propFileName,log); 
         }  
         catch( Exception  e)
         {
            if(trace)
               log.trace("Could not load properties file:" + propFileName, e);
         }
         if(props != null)
         {
            try
            {
               processRoles(group, props);
            }
            catch (Exception e)
            {
               if(trace)
                  log.trace("Could not process roles:", e);
            }
         } 
      } 
      
      return new Group[] {group};
   } 
   
   /**
    * Get the Group called as "Roles" from the authenticated subject
    * 
    * @return Group representing Roles
    */
   private Group getExistingRolesFromSubject()
   {
      Iterator<? extends Principal> iter = subject.getPrincipals().iterator();
      while(iter.hasNext())
      {
         Principal p = (Principal)iter.next();
         if(p instanceof Group)
         {
           Group g = (Group) p;
           if("Roles".equals(g.getName()))
              return g;
         } 
      }
      return null;
   }

   /**
    * Process the group with the roles that are mapped in the 
    * properies file
    * @param group Group that needs to be processed
    * @param props Properties file
    */
   private void processRoles(Group group,Properties props) throws Exception
   {
      Enumeration<?> enumer = props.propertyNames();
      while(enumer.hasMoreElements())
      {
         String roleKey = (String)enumer.nextElement();
         String comma_separated_roles = props.getProperty(roleKey);
         Principal pIdentity = createIdentity(roleKey);
         if(group.isMember(pIdentity))
            Util.parseGroupMembers(group,comma_separated_roles,this);
         if(REPLACE_ROLE)
            group.removeMember(pIdentity); 
      } 
   }
}