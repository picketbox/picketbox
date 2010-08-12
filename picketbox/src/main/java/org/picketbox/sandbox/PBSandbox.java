/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.picketbox.sandbox;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;

/**
 * <p>
 * A class to test the library requirements
 * of PicketBox code base.
 * </p>
 * 
 * <p>
 * We test the authentication and authorization
 * aspects.
 * </p>
 * @author Anil.Saldhana@redhat.com
 * @since Feb 1, 2010
 */
public class PBSandbox
{
   private static String securityDomainName = "test"; 

   /**
    * @param args
    */
   public static void main(String[] args) throws Exception
   {
      testAuthentication();
      testAuthorization();
   }
   
   private static void testAuthentication()
   {
      SecurityFactory.prepare();
      try
      { 
         String configFile = "config/authentication.conf";
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         if(am == null)
            throw new RuntimeException("Authentication Manager is null"); 

         Subject subject = new Subject();
         Principal principal = getPrincipal("anil");
         Object credential = new String("pass");

         boolean result = am.isValid(principal, credential); 
         if(result == false)
            throw new RuntimeException("Authentication Failed");
         
         result = am.isValid(principal, credential, subject);
         if(result == false)
            throw new RuntimeException("Authentication Failed");
         
         if(subject.getPrincipals().size() < 1)
            throw new RuntimeException("Subject has zero principals"); 
         System.out.println("Authentication Successful");
      }
      finally
      {
         SecurityFactory.release();
      }
   }
   
   private static void testAuthorization() throws Exception
   {
      SecurityFactory.prepare();
      try
      {
         String configFile = "config/authorization.conf";
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         if(am == null)
            throw new RuntimeException("Authentication Manager is null"); 

         Subject subject = new Subject();
         Principal principal = getPrincipal("anil");
         Object credential = new String("pass");

         boolean result = am.isValid(principal, credential, subject);
         if(result == false) 
            throw new RuntimeException("InValid Auth");

         if(subject.getPrincipals().size() < 1)
            throw new RuntimeException("Subject has zero principals"); 
         
         AuthorizationManager authzM = SecurityFactory.getAuthorizationManager(securityDomainName);
         if(authzM == null)
            throw new RuntimeException("Authorization Manager is null"); 
         
         Resource resource = getResource();
         int decision = authzM.authorize(resource, subject);
         if(decision != AuthorizationContext.PERMIT)
            throw new RuntimeException("Authz is not permit");
         
         System.out.println("Authorization successful");
      }
      finally
      {
         SecurityFactory.release();
      }
   }
   
   private static Principal getPrincipal(final String name)
   {
      return new Principal()
      {
         public String getName()
         {
            return name;
         }
      };
   }

   
   private static Resource getResource()
   {
      return new Resource()
      {
         HashMap<String,Object> contextMap = new HashMap<String,Object>();
         
         public ResourceType getLayer()
         {
            return ResourceType.POJO;
         }

         public Map<String, Object> getMap()
         {
            return contextMap;
         }

         public void add(String key, Object value)
         {
             contextMap.put(key, value);
         }
      };
   }
}