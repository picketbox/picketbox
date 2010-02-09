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
package org.jboss.security;

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;

/** An implementation of Authenticator that obtains the username and password
 * from the current SecurityAssociation state.
 *
 * @author Scott.Stark@jboss.org
 * @version $Revision$
 */
public class SecurityAssociationAuthenticator extends Authenticator
{
   protected PasswordAuthentication getPasswordAuthentication()
   {
      SecurityActions sa = SecurityActions.UTIL.getSecurityActions();
      Principal principal = sa.getPrincipal();
      Object credential = sa.getCredential();
      String name = principal != null ? principal.getName() : null;
      char[] password = {};
      if( credential != null )
      {
         if( password.getClass().isInstance(credential) )
            password = (char[]) credential;
         else
            password = credential.toString().toCharArray();
      }
      PasswordAuthentication auth = new PasswordAuthentication(name, password);
      return auth;
   }

   interface SecurityActions
   {
      class UTIL
      {
         static SecurityActions getSecurityActions()
         {
            return System.getSecurityManager() == null ? NON_PRIVILEGED : PRIVILEGED;
         }
      }

      SecurityActions NON_PRIVILEGED = new SecurityActions()
      {
         public Principal getPrincipal()
         {
            return SecurityAssociation.getPrincipal();
         }

         public Object getCredential()
         {
            return SecurityAssociation.getCredential();
         }
      };

      SecurityActions PRIVILEGED = new SecurityActions()
      {
         private final PrivilegedAction<Principal> getPrincipalAction = new PrivilegedAction<Principal>()
         {
            public Principal run()
            {
               return SecurityAssociation.getPrincipal();
            }
         };

         private final PrivilegedAction<Object> getCredentialAction = new PrivilegedAction<Object>()
         {
            public Object run()
            {
               return SecurityAssociation.getCredential();
            }
         };

         public Principal getPrincipal()
         {
            return (Principal)AccessController.doPrivileged(getPrincipalAction);
         }

         public Object getCredential()
         {
            return AccessController.doPrivileged(getCredentialAction);
         }
      };

      Principal getPrincipal();

      Object getCredential();
   }
}
