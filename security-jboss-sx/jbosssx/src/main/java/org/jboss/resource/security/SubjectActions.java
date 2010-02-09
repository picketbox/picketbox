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

import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.acl.Group;
import java.util.Iterator;
import java.util.Set;

import javax.resource.spi.ManagedConnectionFactory;
import javax.resource.spi.security.PasswordCredential;
import javax.security.auth.Subject;

import org.jboss.security.SimpleGroup;

/**
 * Common package privileged actions.
 * 
 * @author Scott.Stark@jboss.org
 * @version $Revision: 71545 $
 */

@SuppressWarnings("unchecked")
class SubjectActions
{
   interface AddRolesActions
   {
      AddRolesActions PRIVILEGED = new AddRolesActions()
      {
         public void addRoles(final Subject subject, final Set roles)
         {
            AccessController.doPrivileged(new PrivilegedAction()
            {
               public Object run()
               {
                  addSubjectRoles(subject, roles);
                  return null;
               }
            });
         }
      };

      AddRolesActions NON_PRIVILEGED = new AddRolesActions()
      {
         public void addRoles(final Subject subject, final Set roles)
         {
            addSubjectRoles(subject, roles);
         }
      };

      void addRoles(Subject subject, Set roles);
   }

   static class AddCredentialsAction implements PrivilegedAction
   {
      Subject subject;
      PasswordCredential cred;
      AddCredentialsAction(Subject subject, PasswordCredential cred)
      {
         this.subject = subject;
         this.cred = cred;
      }
      public Object run()
      {
         subject.getPrivateCredentials().add(cred);
         return null;
      }
   }
   static class AddPrincipalsAction implements PrivilegedAction
   {
      Subject subject;
      Principal p;
      AddPrincipalsAction(Subject subject, Principal p)
      {
         this.subject = subject;
         this.p = p;
      }
      public Object run()
      {
         subject.getPrincipals().add(p);
         return null;
      }
   }
   static class RemoveCredentialsAction implements PrivilegedAction
   {
      Subject subject;
      ManagedConnectionFactory mcf;
      RemoveCredentialsAction(Subject subject, ManagedConnectionFactory mcf)
      {
         this.subject = subject;
         this.mcf = mcf;
      }
      public Object run()
      {
         Iterator i = subject.getPrivateCredentials().iterator();
         while( i.hasNext() )
         {
            Object o = i.next();
            if ( o instanceof PasswordCredential )
            {
               PasswordCredential pc = (PasswordCredential) o;
               if( pc.getManagedConnectionFactory() == mcf )
                  i.remove();
            }
         }
         return null;
      }
   }

   static void addCredentials(Subject subject, PasswordCredential cred)
   {
      AddCredentialsAction action = new AddCredentialsAction(subject, cred);
      AccessController.doPrivileged(action);
   }
   static void addPrincipals(Subject subject, Principal p)
   {
      AddPrincipalsAction action = new AddPrincipalsAction(subject, p);
      AccessController.doPrivileged(action);
   }
   static void removeCredentials(Subject subject, ManagedConnectionFactory mcf)
   {
      RemoveCredentialsAction action = new RemoveCredentialsAction(subject, mcf);
      AccessController.doPrivileged(action);
   }

   static void addRoles(Subject subject, Set runAsRoles)
   {
      if( System.getSecurityManager() != null )
      {
         AddRolesActions.PRIVILEGED.addRoles(subject, runAsRoles);
      }
      else
      {
         AddRolesActions.NON_PRIVILEGED.addRoles(subject, runAsRoles);         
      }
   }

   private static Group addSubjectRoles(Subject theSubject, Set roles)
   {
      Set subjectGroups = theSubject.getPrincipals(Group.class);
      Iterator iter = subjectGroups.iterator();
      Group roleGrp = null;
      while (iter.hasNext())
      {
         Group grp = (Group) iter.next();
         String name = grp.getName();
         if (name.equals("Roles"))
            roleGrp = grp;
      }

      // Create the Roles group if it was not found
      if (roleGrp == null)
      {
         roleGrp = new SimpleGroup("Roles");
         theSubject.getPrincipals().add(roleGrp);
      }

      iter = roles.iterator();
      while (iter.hasNext())
      {
         Principal role = (Principal) iter.next();
         roleGrp.addMember(role);
      }
      return roleGrp;
   }

}
