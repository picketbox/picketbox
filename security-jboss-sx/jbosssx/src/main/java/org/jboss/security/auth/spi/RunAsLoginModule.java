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

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

import org.jboss.security.RunAsIdentity;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;

/** A login module that establishes a run-as role for the duration of the login
 * phase of authentication. It can be used to allow another login module
 * interact with a secured EJB that provides authentication services.
 *
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
public class RunAsLoginModule implements LoginModule
{
   private String roleName;
   private String principalName;
   private boolean pushedRole;

   /** Look for the roleName option that specifies the role to use as the
    * run-as role. If not specified a default role name of nobody is used.
    */
   public void initialize(Subject subject, CallbackHandler handler,
      Map<String,?> sharedState, Map<String,?> options)
   {
      roleName = (String) options.get("roleName");
      if( roleName == null )
         roleName = "nobody";

      principalName = (String) options.get("principalName");
      if( principalName == null )
         principalName = "nobody";
   }

   /** Push the run as role using the SecurityAssociation.pushRunAsIdentity method
    *@see SecurityAssociation#pushRunAsIdentity(RunAsIdentity)
    */
   public boolean login()
   {
      RunAsIdentity runAsRole = new RunAsIdentity(roleName, principalName);
      SecurityContextAssociation.pushRunAsIdentity(runAsRole);
      pushedRole = true;
      return true;
   }

   /** Calls abort to pop the run-as role
    */
   public boolean commit()
   {
      return abort();
   }

   /** Pop the run as role using the SecurityAssociation.popRunAsIdentity method
    *@see SecurityAssociation#popRunAsIdentity()
    */
   public boolean abort()
   {
      if( pushedRole == false )
         return false;

      SecurityContextAssociation.popRunAsIdentity();
      return true;
   }

   public boolean logout()
   {
      return true;
   }
}
