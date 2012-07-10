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

import java.lang.reflect.Constructor;
import java.security.Principal;

import javax.security.auth.Subject;
 

/**
 *  Factory class to create Security Context instances
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Dec 28, 2006 
 *  @version $Revision$
 */
@SuppressWarnings("unchecked")
public class SecurityContextFactory
{      
   private static String defaultFQN = "org.jboss.security.plugins.JBossSecurityContext";
   
   private static String defaultUtilClassFQN = "org.jboss.security.plugins.JBossSecurityContextUtil";
   
   private static Class<? extends SecurityContext> defaultSecurityContextClass = null;
   private static Class<? extends SecurityContextUtil> defaultUtilClass = null;
   
   /**
    * Classloader.loadClass is a synchronized method in the JDK. Under heavy concurrent requests,
    * a loadClass() operation can be extremely troublesome for performance
    */
   static
   {
      try
      {
         defaultSecurityContextClass = (Class<? extends SecurityContext>) SecuritySPIActions.getCurrentClassLoader(SecurityContextFactory.class).loadClass(defaultFQN);
      }
      catch(Exception ignore)
      {
         try
         {
            defaultSecurityContextClass = (Class<? extends SecurityContext>) SecuritySPIActions.getContextClassLoader().loadClass(defaultFQN);
         }
         catch (Exception e)
         {
         }
      }
      try
      {
         defaultUtilClass = (Class<? extends SecurityContextUtil>) SecuritySPIActions.getCurrentClassLoader(SecurityContextFactory.class).loadClass(defaultUtilClassFQN);
      }
      catch(Exception ignore)
      {
         try
         {
            defaultUtilClass = (Class<? extends SecurityContextUtil>) SecuritySPIActions.getContextClassLoader().loadClass(defaultUtilClassFQN);
         }
         catch(Exception e)
         {
         }
      }
   }

   /**
    * Create a security context 
    * @param securityDomain Security Domain driving the context
    * @return
    * @throws Exception 
    */
   public static SecurityContext createSecurityContext(String securityDomain) throws Exception
   {
      if(defaultSecurityContextClass != null)
         return createSecurityContext(securityDomain, defaultSecurityContextClass);
      return createSecurityContext(securityDomain, defaultFQN, SecuritySPIActions.getCurrentClassLoader(SecurityContextFactory.class));
   }
   
   /**
    * Create a security context 
    * @param securityDomain Security Domain driving the context
    * @param classLoader ClassLoader to use
    * @return
    * @throws Exception 
    */
   public static SecurityContext createSecurityContext(String securityDomain, ClassLoader classLoader) throws Exception
   {
      if(defaultSecurityContextClass != null)
         return createSecurityContext(securityDomain, defaultSecurityContextClass);
      return createSecurityContext(securityDomain, defaultFQN, classLoader);
   }
   
   /**
    * Construct a SecurityContext
    * @param securityDomain  The Security Domain
    * @param fqnClass  Fully Qualified Name of the SecurityContext Class
    * @return an instance of SecurityContext
    * @throws Exception
    */
   public static SecurityContext createSecurityContext(String securityDomain,
         String fqnClass) throws Exception
   {
      return createSecurityContext(securityDomain, fqnClass, SecuritySPIActions.getCurrentClassLoader(SecurityContextFactory.class));
   }
   
   /**
    * Construct a SecurityContext
    * @param securityDomain  The Security Domain
    * @param fqnClass  Fully Qualified Name of the SecurityContext Class
    * @param classLoader ClassLoader to use
    * @return an instance of SecurityContext
    * @throws Exception
    */
   public static SecurityContext createSecurityContext(String securityDomain,
         String fqnClass, ClassLoader classLoader) throws Exception
   {
      if(securityDomain == null)
         throw PicketBoxMessages.MESSAGES.invalidNullArgument("security domain");
      if(fqnClass == null)
         throw PicketBoxMessages.MESSAGES.invalidNullArgument("fqnClass");
      defaultSecurityContextClass = getContextClass(fqnClass, classLoader);
      return createSecurityContext(securityDomain, defaultSecurityContextClass);
   }
   
   
   /**
    * Create a security context given the class
    * This method exists because classloader.loadClass is an expensive
    * operation due to synchronization
    * @param securityDomain
    * @param clazz
    * @return
    * @throws Exception
    */
   public static SecurityContext createSecurityContext(String securityDomain,
         Class<? extends SecurityContext> clazz) throws Exception
   {
      if(securityDomain == null)
         throw PicketBoxMessages.MESSAGES.invalidNullArgument("security domain");
       if(clazz == null)
         throw PicketBoxMessages.MESSAGES.invalidNullArgument("clazz");
      //Get the CTR
      Constructor<? extends SecurityContext> ctr = clazz.getConstructor(new Class[]{String.class});
      return (SecurityContext) ctr.newInstance(new Object[]{securityDomain}); 
   }
   
   /**
    * Create a security context
    * @param p Principal
    * @param cred Credential
    * @param s Subject
    * @param securityDomain SecurityDomain
    * @return
    * @throws Exception 
    * @see #createSecurityContext(String)
    */
   public static SecurityContext createSecurityContext(Principal p, 
         Object cred, Subject s, String securityDomain) throws Exception
   {
      return createSecurityContext(p, cred, s, securityDomain, SecuritySPIActions.getCurrentClassLoader(SecurityContextFactory.class));
   }
   
   /**
    * Create a security context
    * @param p Principal
    * @param cred Credential
    * @param s Subject
    * @param securityDomain SecurityDomain
    * @param classLoader ClassLoader to use
    * @return
    * @throws Exception 
    * @see #createSecurityContext(String)
    */
   public static SecurityContext createSecurityContext(Principal p, 
         Object cred, Subject s, String securityDomain, ClassLoader classLoader) throws Exception
   {
      SecurityContext jsc = createSecurityContext(securityDomain, classLoader);
      jsc.getUtil().createSubjectInfo(p,cred,s);
      return jsc;
   }
   
   /**
    * Create a security context
    * @param p Principal
    * @param cred Credential
    * @param s Subject
    * @param securityDomain SecurityDomain
    * @param fqnClass FQN of the SecurityContext class to be instantiated
    * @param classLoader ClassLoader to use
    * @return
    * @see #createSecurityContext(String)
    * @throws Exception
    */
   public static SecurityContext createSecurityContext(Principal p, 
         Object cred,Subject s, String securityDomain, String fqnClass, ClassLoader classLoader) 
   throws Exception
   {
      SecurityContext sc = createSecurityContext(securityDomain, fqnClass, classLoader);
      sc.getUtil().createSubjectInfo(p,cred,s);
      return sc;
   }
   
   /**
    * Return an instance of the SecurityContextUtil
    * @param sc SecurityContext
    * @return
    */
   public static SecurityContextUtil createUtil(SecurityContext sc) throws Exception
   {
      return createUtil(sc, SecuritySPIActions.getCurrentClassLoader(SecurityContextFactory.class));
   }
   
   /**
    * Return an instance of the SecurityContextUtil
    * @param sc SecurityContext
    * @param classLoader ClassLoader to use
    * @return
    */
   public static SecurityContextUtil createUtil(SecurityContext sc, ClassLoader classLoader) throws Exception
   {
      Class<? extends SecurityContextUtil> clazz = defaultUtilClass;
      
      if(clazz  == null)
      {
         clazz = (Class<? extends SecurityContextUtil>) loadClass(defaultUtilClassFQN, classLoader);
         defaultUtilClass = clazz; 
      }
      
      //Get the CTR
      Constructor<?> ctr = clazz.getConstructor(new Class[]{SecurityContext.class});
      Object obj = ctr.newInstance(new Object[]{sc});
      return SecurityContextUtil.class.cast(obj);
   }
   
   /**
    * Return an instance of the SecurityContextUtil given a FQN of the util class
    * @param sc SecurityContext
    * @param utilFQN fqn of the util class
    * @return
    */ 
   public static SecurityContextUtil createUtil(SecurityContext sc, String utilFQN) throws Exception
   {
      return createUtil(sc, utilFQN, SecuritySPIActions.getCurrentClassLoader(SecurityContextFactory.class));
   }
   
   /**
    * Return an instance of the SecurityContextUtil given a FQN of the util class
    * @param sc SecurityContext
    * @param utilFQN fqn of the util class
    * @param classLoader ClassLoader to use
    * @return
    */ 
   public static SecurityContextUtil createUtil(SecurityContext sc, String utilFQN, ClassLoader classLoader) throws Exception
   {
      Class<?> clazz = null;
      try
      {
         clazz = classLoader.loadClass(utilFQN);
      }
      catch (Exception e)
      {
         ClassLoader tcl = SecuritySPIActions.getContextClassLoader();
         clazz = tcl.loadClass(utilFQN);
      }
      //Get the CTR
      Constructor<? extends SecurityContextUtil> ctr = 
         (Constructor<? extends SecurityContextUtil>) clazz.getConstructor(new Class[]{SecurityContext.class});
      return ctr.newInstance(new Object[]{sc});
   }
   
   /**
    * Return an instance of the SecurityContextUtil given a Class instance of the util class
    * @param sc SecurityContext
    * @return
    */
   public static SecurityContextUtil createUtil(SecurityContext sc, 
         Class<? extends SecurityContextUtil> utilClazz) throws Exception
   {
      //Get the CTR
      Constructor<? extends SecurityContextUtil> ctr = utilClazz.getConstructor(new Class[]{SecurityContext.class});
      return ctr.newInstance(new Object[]{sc}); 
   }
   
   /**
    * Set the default security context fqn
    * @param fqn
    */
   public static void setDefaultSecurityContextFQN(String fqn)
   {
      defaultFQN = fqn;
      defaultSecurityContextClass = null; 
   }
   
   
   /**
    * Set the default util class fqn
    * @param fqn
    */
   public static void setDefaultSecurityContextUtilFQN(String fqn)
   {
      defaultUtilClassFQN = fqn;
      defaultUtilClass = null; //reset
   }
   
   /**
    * Load a class
    * @param fqn
    * @param classLoader
    * @return
    * @throws Exception
    */
   private static Class<?> loadClass(String fqn, ClassLoader classLoader) throws Exception
   {
      try
      {
         return classLoader.loadClass(fqn);
      }
      catch (Exception e)
      {
         ClassLoader tcl = SecuritySPIActions.getContextClassLoader();
         return tcl.loadClass(fqn);
      }
   }
    
   private static Class<SecurityContext> getContextClass(String className, ClassLoader classLoader) throws Exception
   {
      try
      {
         return (Class<SecurityContext>) classLoader.loadClass(className);
      }
      catch (Exception e)
      {
         ClassLoader tcl = SecuritySPIActions.getContextClassLoader();
         return (Class<SecurityContext>) tcl.loadClass(className);
      }
   }
}