/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
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
package org.jboss.security.identity;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.WeakHashMap;
 
/**
 *  Factory to create roles
 *  @author Anil.Saldhana@redhat.com
 *  @since  Dec 21, 2007 
 *  @version $Revision$
 */
public class RoleFactory
{
   private static String SIMPLE_ROLE_CLASS = "org.jboss.security.identity.plugins.SimpleRole";
   private static String SIMPLE_ROLEGROUP_CLASS = "org.jboss.security.identity.plugins.SimpleRoleGroup";
   
   private static Map<String, Class<?> > clazzMap = new WeakHashMap<String, Class<?>>();
   
   public static Role createRole(final String name) throws PrivilegedActionException
   {
     return AccessController.doPrivileged(new PrivilegedExceptionAction<Role>()
     { 
      public Role run() throws Exception
      { 
         Class<?> clazz = clazzMap.get(SIMPLE_ROLE_CLASS);
         if( clazz == null )
         {
            ClassLoader tcl = Thread.currentThread().getContextClassLoader();
            clazz = tcl.loadClass(SIMPLE_ROLE_CLASS); 
         }
         
         Constructor<?> ctr = clazz.getConstructor(new Class[] {String.class});
         return (Role) ctr.newInstance(new Object[]{name});
      }  
     });  
   }
   
   public static RoleGroup createRoleGroup(final String name) throws PrivilegedActionException
   {
     return AccessController.doPrivileged(new PrivilegedExceptionAction<RoleGroup>()
     { 
      public RoleGroup run() throws Exception
      { 
         Class<?> clazz = clazzMap.get(SIMPLE_ROLEGROUP_CLASS);
         if( clazz == null )
         {
            ClassLoader tcl = Thread.currentThread().getContextClassLoader();
            clazz = tcl.loadClass(SIMPLE_ROLEGROUP_CLASS); 
         }
          
         Constructor<?> ctr = clazz.getConstructor(new Class[] {String.class});
         return (RoleGroup) ctr.newInstance(new Object[]{name});
      }  
     });  
   } 
   
   public static void setSimpleRoleClass(String fqn)
   {
      SIMPLE_ROLE_CLASS = fqn;
   }
   
   public static void setSimpleRoleGroupClass(String fqn)
   {
      SIMPLE_ROLEGROUP_CLASS = fqn;
   }
}
