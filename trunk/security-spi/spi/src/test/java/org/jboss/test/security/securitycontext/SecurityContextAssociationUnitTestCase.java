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
package org.jboss.test.security.securitycontext;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;

import junit.framework.TestCase;

/**
 * Unit Test the SecurityContextAssociation
 * @author anil.saldhana@redhat.com
 */
public class SecurityContextAssociationUnitTestCase extends TestCase
{
   private SecurityContext sc = new TestSecurityContext("test");
   
   public void testClientSide() throws Exception
   {
      assertFalse("SCA is not client", SecurityContextAssociation.isClient());
      SecurityContextAssociation.setClient();
      assertTrue("SCA is client", SecurityContextAssociation.isClient()); 
      
      //Test the VMwide association
      SecurityContextAssociation.setSecurityContext(sc);
      
      //Spawn two threads and see that the same sc is there
      Thread p = new Thread(new SCThread(1));
      p.start(); 
      
      Thread q = new Thread(new SCThread(2));
      q.start();
      
      Thread.sleep(1000); 
   }
   
   class SCThread implements Runnable
   { 
      int num = 0;
      
      public SCThread(int n)
      {
         this.num = n;
      }
      
      public void run()
      {
         System.out.println("Inside Thread:" + num);
         
         SecurityContext secCtx = SecurityContextAssociation.getSecurityContext();
         if(secCtx == null)
            throw new RuntimeException("Security Context is null:" + num);
         if(!(secCtx == sc))
            throw new RuntimeException("Not the same sec ctx:" + num);
         
         System.out.println("Thread " + num + " passed SC test");
      } 
   }
}