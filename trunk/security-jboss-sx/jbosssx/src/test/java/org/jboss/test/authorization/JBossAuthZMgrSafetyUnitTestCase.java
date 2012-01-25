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
package org.jboss.test.authorization;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceType;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.plugins.JBossAuthorizationManager;
import org.jboss.test.util.SecurityTestUtil;
 
/**
 *  Test the concurrency correctness of JBossAuthorizationManager
 *  @author Anil.Saldhana@redhat.com
 *  @since  Dec 15, 2007 
 *  @version $Revision$
 */
public class JBossAuthZMgrSafetyUnitTestCase extends TestCase
{  
   private JBossAuthorizationManager am = new JBossAuthorizationManager("other");
   
   protected void setUp() throws Exception
   { 
      ApplicationPolicy ap = SecurityTestUtil.getApplicationPolicy("other", null);
      SecurityTestUtil.setUpRegularConfiguration(ap);
   }
   
   public void testThreadSafety() throws Exception
   {
     //Create 3 authz threads and 2 authzsetandcall threads
     AuthzCallable t1 = new AuthzCallable();
     AuthzSetAndCall t2 = new AuthzSetAndCall();
     AuthzCallable t3 = new AuthzCallable();
     AuthzSetAndCall t4 = new AuthzSetAndCall();
     AuthzCallable t5 = new AuthzCallable();
     
     ExecutorService es = Executors.newFixedThreadPool(5) ;
     assertTrue(es.submit(t1).get());
     assertTrue(es.submit(t2).get());
     assertTrue(es.submit(t3).get());
     assertTrue(es.submit(t4).get());
     assertTrue(es.submit(t5).get());
   }
   
   private class AuthzCallable implements Callable<Boolean>
   { 
      private TestResource resource = new TestResource();
      public Boolean call() throws Exception
      { 
         RoleGroup role = SecurityTestUtil.getRoleGroup("roleA");
         Subject subject = new Subject();
         return am.authorize(resource, subject, role) == AuthorizationContext.PERMIT;
      } 
   }
   
   private class AuthzSetAndCall implements Callable<Boolean>
   { 
      private TestResource resource = new TestResource();
      public Boolean call() throws Exception
      { 
         RoleGroup role = SecurityTestUtil.getRoleGroup("roleA");
         Subject subject = new Subject();
         return am.authorize(resource, subject, role) == AuthorizationContext.PERMIT; 
      } 
   }
   
   private class TestResource implements Resource
   { 
      HashMap<String,Object> contextMap = new HashMap<String,Object>();
      
      public ResourceType getLayer()
      {
         return ResourceType.WEB;
      }

      public Map<String, Object> getMap()
      {
         return contextMap;
      }

      public void add(String key, Object value)
      {
         contextMap.put(key, value);    
      } 
   }  
}