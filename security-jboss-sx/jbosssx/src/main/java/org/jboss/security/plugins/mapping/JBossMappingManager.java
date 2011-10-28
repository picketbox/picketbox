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
package org.jboss.security.plugins.mapping;

import java.util.ArrayList;
import java.util.Map;
import java.util.WeakHashMap;

import org.jboss.logging.Logger;
import org.jboss.security.ErrorCodes;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityUtil;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.MappingInfo;
import org.jboss.security.config.SecurityConfiguration; 
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingManager;
import org.jboss.security.mapping.MappingProvider;
import org.jboss.security.mapping.config.MappingModuleEntry;


/**
 *  JBoss implementation of Mapping Manager 
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 9, 2007 
 *  @version $Revision$
 */
public class JBossMappingManager implements MappingManager
{   
   protected static final Logger log = Logger.getLogger(JBossMappingManager.class); 
   protected boolean trace = log.isTraceEnabled();  
   
   private String securityDomain;

   private static Map<String, Class<?> > clazzMap = new WeakHashMap<String, Class<?>>();

   public JBossMappingManager(String domain)
   {
      this.securityDomain = SecurityUtil.unprefixSecurityDomain(domain);  
   }
   
   
   public <T> MappingContext<T> getMappingContext(String mappingType)
   {
      //Apply Mapping Logic  
      ApplicationPolicy aPolicy = SecurityConfiguration.getApplicationPolicy(securityDomain);
      
      if(aPolicy == null)
      {
         String defaultDomain = SecurityConstants.DEFAULT_APPLICATION_POLICY;
         if(trace)
            log.trace("Application Policy not found for domain=" + securityDomain +
                  ".Mapping framework will use the default domain:" + defaultDomain);
         aPolicy = SecurityConfiguration.getApplicationPolicy(defaultDomain); 
      } 
      if(aPolicy == null )
         throw new IllegalStateException(ErrorCodes.NULL_VALUE + "Application Policy is null for the security domain:" 
               + securityDomain);
      
      MappingContext<T> mc = null;
      MappingInfo rmi = aPolicy.getMappingInfo(mappingType);  

      if( rmi != null)
         mc = generateMappingContext(mc, rmi);
      
      return mc; 
   }
   
   
   /**
    * @see SecurityContext#getMappingContext(String)
    */
   @SuppressWarnings("deprecation")
   public <T> MappingContext<T> getMappingContext(Class<T> mappingType)
   { 
      //Apply Mapping Logic  
      ApplicationPolicy aPolicy = SecurityConfiguration.getApplicationPolicy(securityDomain);
      
      if(aPolicy == null)
      {
         String defaultDomain = SecurityConstants.DEFAULT_APPLICATION_POLICY;
         if(trace)
            log.trace("Application Policy not found for domain=" + securityDomain +
                  ".Mapping framework will use the default domain:" + defaultDomain);
         aPolicy = SecurityConfiguration.getApplicationPolicy(defaultDomain); 
      } 
      if(aPolicy == null )
         throw new IllegalStateException(ErrorCodes.NULL_VALUE + "Application Policy is null for the security domain:" 
               + securityDomain);
      
      MappingContext<T> mc = null;
      MappingInfo rmi = aPolicy.getMappingInfo(mappingType); 
      if( rmi != null)
        mc = generateMappingContext(mc, rmi);
      
      return mc; 
   }


   private <T> MappingContext<T> generateMappingContext(MappingContext<T> mc, MappingInfo rmi)
   {
      MappingModuleEntry[] mpe = rmi.getMappingModuleEntry();
      ArrayList<MappingProvider<T>> al = new ArrayList<MappingProvider<T>>();

      for(int i = 0 ; i < mpe.length; i++)
      { 
         MappingProvider<T> mp = getMappingProvider(mpe[i]);
         if(mp != null)
            al.add(mp); 
      }
      return new MappingContext<T>(al); 
   } 
    
   public String getSecurityDomain()
   { 
      return this.securityDomain;
   }

   @SuppressWarnings("unchecked")
   private <T> MappingProvider<T> getMappingProvider(MappingModuleEntry mme)
   {
      MappingProvider<T> mp = null;
      try
      {
         String fqn = mme.getMappingModuleName();
         Class<?> clazz = clazzMap.get(fqn);
         if( clazz == null )
         {
            try
            {
               clazz = getClass().getClassLoader().loadClass(fqn);
            }
            catch (Exception e)
            {
               ClassLoader tcl = SecurityActions.getContextClassLoader();
               clazz = tcl.loadClass(fqn);
            }
            clazzMap.put(fqn, clazz); 
         } 
         mp = (MappingProvider<T>) clazz.newInstance();
         mp.init(mme.getOptions());
      }
      catch(Exception e)
      {
         if(trace)
            log.trace("Error in getting Mapping Provider",e);
      } 
      return mp; 
   }
}