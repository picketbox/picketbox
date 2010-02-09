/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2006, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
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
package org.jboss.resource.security;

import java.io.UnsupportedEncodingException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;

import org.jboss.security.RunAsIdentity;
import org.jboss.security.SecurityAssociation;

/** PrivilegedActions used by this package
 * 
 * @author Scott.Stark@jboss.org
 * @version $Revision: 71545 $
 */
class GetPrincipalInfoAction
{
   /* Obtain the password credential by trying char[], byte[],
    and toString()
    */
   private static char[] getPassword()
   {
      Object credential = SecurityAssociation.getCredential();
      char[] password = null;
       if( credential instanceof char[] )
       {
          password = (char[]) credential;
       }
       else if( credential instanceof byte[] )
       {
          try
          {
             String tmp = new String((byte[]) credential, "UTF-8");
             password = tmp.toCharArray();
          }
          catch (UnsupportedEncodingException e)
          {
             throw new SecurityException(e.getMessage());
          }
       }
       else if( credential != null )
       {
          String tmp = credential.toString();
          password = tmp.toCharArray();
       }
      return password;
   }


   @SuppressWarnings("unchecked")
   interface PrincipalActions
   {
      PrincipalActions PRIVILEGED = new PrincipalActions()
      {
         private final PrivilegedAction peekAction = new PrivilegedAction()
         {
            public Object run()
            {
               return SecurityAssociation.peekRunAsIdentity();
            }
         };

         private final PrivilegedAction getPrincipalAction = new PrivilegedAction()
         {
            public Object run()
            {
               return SecurityAssociation.getPrincipal();
            }
         };

         private final PrivilegedAction getCredentialAction = new PrivilegedAction()
         {
            public Object run()
            {
               return getPassword();
            }
         };

         public RunAsIdentity peek()
         {
            return (RunAsIdentity)AccessController.doPrivileged(peekAction);
         }

         public Principal getPrincipal()
         {
            return (Principal)AccessController.doPrivileged(getPrincipalAction);
         }

         public char[] getCredential()
         {
            return (char[]) AccessController.doPrivileged(getCredentialAction);
         }
      };

      PrincipalActions NON_PRIVILEGED = new PrincipalActions()
      {
         public RunAsIdentity peek()
         {
            return SecurityAssociation.peekRunAsIdentity();
         }

         public Principal getPrincipal()
         {
            return SecurityAssociation.getPrincipal();
         }

         public char[] getCredential()
         {
            return getPassword();
         }
      };

      Principal getPrincipal();
      char[] getCredential();
      RunAsIdentity peek();
   }

   static Principal getPrincipal()
   {
      Principal principal;
      if(System.getSecurityManager() == null)
      {
         principal = PrincipalActions.NON_PRIVILEGED.getPrincipal();
      }
      else
      {
         principal = PrincipalActions.PRIVILEGED.getPrincipal();
      }
      return principal;
   }
   static char[] getCredential()
   {
      char[] credential;
      if(System.getSecurityManager() == null)
      {
         credential = PrincipalActions.NON_PRIVILEGED.getCredential();
      }
      else
      {
         credential = PrincipalActions.PRIVILEGED.getCredential();
      }
      return credential;
   }
   static RunAsIdentity peekRunAsIdentity()
   {
      if(System.getSecurityManager() == null)
      {
         return PrincipalActions.NON_PRIVILEGED.peek();
      }
      else
      {
         return PrincipalActions.PRIVILEGED.peek();
      }
   }

}
