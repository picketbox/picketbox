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
 
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.jboss.security.SecurityContext;


/**
 *  Security Context association in a threadlocal
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Dec 27, 2006 
 *  @version $Revision$
 */
public class SecurityContextAssociation
{
   /**
    * A flag that denotes whether SCA operates in a client side vm-wide mode
    */
   private static boolean SERVER = true;
   
   private static SecurityContext securityContext = null;
   
   private static RuntimePermission SetSecurityContextPermission = 
      new RuntimePermission("org.jboss.security.setSecurityContext");
   
   private static RuntimePermission GetSecurityContextPermission = 
      new RuntimePermission("org.jboss.security.getSecurityContext");
   
   private static RuntimePermission ClearSecurityContextPermission = 
      new RuntimePermission("org.jboss.security.clearSecurityContext");
   
   /**
    * Flag to indicate whether threads that are spawned inherit the security context from parent
    * Set this to false if you do not want inheritance. By default the context is inherited.
    */
   public static final String SECURITYCONTEXT_THREADLOCAL = "org.jboss.security.context.ThreadLocal";
   
   /**
    * In JBoss AS4, the SecurityAssociation inheritance is managed with a different system property
    * This flag should be private and not visible.
    */
   private static final String SECURITYASSOCIATION_THREADLOCAL = "org.jboss.security.SecurityAssociation.ThreadLocal";
   
   private static ThreadLocal<SecurityContext> securityContextLocal ;
   
   static
   {
      String saflag = getSystemProperty(SECURITYASSOCIATION_THREADLOCAL, "false");
      String scflag = getSystemProperty(SECURITYCONTEXT_THREADLOCAL, "false");
      
      boolean useThreadLocal = Boolean.valueOf(saflag).booleanValue() || Boolean.valueOf(scflag).booleanValue();
      
      if(useThreadLocal)
      {
         securityContextLocal = new ThreadLocal<SecurityContext>();
      }
      else
      {
         securityContextLocal = new InheritableThreadLocal<SecurityContext>();
      }
   }
   
   /**
    * Indicates whether we are on the client side
    * @return
    */
   public static boolean isClient()
   {
      return !SERVER;
   }
   
   /**
    * Set the VM-wide client side usage
    */
   public static void setClient()
   {
     SERVER = false;
   }
   
   /**
    * Set a security context 
    * @param sc
    */
   public static void setSecurityContext(SecurityContext sc)
   { 
      SecurityManager sm = System.getSecurityManager();
      if(sm != null)
         sm.checkPermission(SetSecurityContextPermission);
      
      if(!SERVER)
         securityContext = sc;
      else
      {
         if(sc == null)
            securityContextLocal.remove();
         else
            securityContextLocal.set(sc); 
      }
   }
   
   /**
    * Get a security context
    * @return
    */
   public static SecurityContext getSecurityContext()
   {
      SecurityManager sm = System.getSecurityManager();
      if(sm != null)
         sm.checkPermission(GetSecurityContextPermission);
      
      if(!SERVER)
         return securityContext;
      
      return securityContextLocal.get();
   } 
   
   /**
    * Clear the current security context
    */
   public static void clearSecurityContext() 
   {
      SecurityManager sm = System.getSecurityManager();
      if(sm != null)
         sm.checkPermission(ClearSecurityContextPermission);
      
      if(!SERVER)
         securityContext = null;
      else
         securityContextLocal.remove();
   }
    
   
   private static String getSystemProperty(final String propertyName, final String defaultString)
   {
      return AccessController.doPrivileged(new PrivilegedAction<String>()
      {
         public String run()
         { 
            return System.getProperty(propertyName, defaultString);
         }
      });
   }
}