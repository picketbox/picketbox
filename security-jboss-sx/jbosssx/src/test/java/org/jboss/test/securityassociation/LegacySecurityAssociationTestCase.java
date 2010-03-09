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
package org.jboss.test.securityassociation;

import java.security.Principal;

import org.jboss.security.RunAs;
import org.jboss.security.RunAsIdentity;
import org.jboss.security.SecurityAssociation;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.SecurityAssociation.SubjectContext;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.test.AbstractJBossSXTest;

//$Id$

/**
 *  Legacy SecurityAssociation deeper integration test case
 *  @author Anil.Saldhana@redhat.com
 *  @since  Aug 22, 2007 
 *  @version $Revision$
 */
public class LegacySecurityAssociationTestCase extends AbstractJBossSXTest
{ 
   public LegacySecurityAssociationTestCase(String name)
   {
      super(name); 
   } 
   
   public void testClientSideSecurityAssociation()
   {
      assertFalse("Client Side", SecurityAssociation.isServer());
      checkSA(false); 
   }
   
   public void testServerSideSecurityAssociation()
   {
      assertFalse("Client Side", SecurityAssociation.isServer());
      SecurityAssociation.setServer();
      assertTrue("Server Side", SecurityAssociation.isServer());
      checkSA(true);
   }
   
   @SuppressWarnings("deprecation")
   public void testSecurityAssociation()
   {
      SecurityAssociation.clear();
      SecurityAssociation.pushSubjectContext(null, new SimplePrincipal("bill"), "password".toCharArray());
      assertEquals("bill", SecurityAssociation.getPrincipal().getName());
      SecurityAssociation.popSubjectContext();
      assertNull(SecurityAssociation.getPrincipal());
   }
   
   public void testCallerPrincipal()
   {
      //With no security context
      assertNull("Caller Principal is null", SecurityAssociation.getCallerPrincipal());
      //Create a security context
      SecurityContext sc =  new JBossSecurityContext("TEST");
      Principal p = new SimplePrincipal("anil");
      sc.getUtil().createSubjectInfo(p, "pass", null);
      SecurityContextAssociation.setSecurityContext(sc);
      
      assertEquals("CallerPrincipal=anil",p,SecurityAssociation.getCallerPrincipal());
      
      //Clear the SecurityContext
      SecurityContextAssociation.clearSecurityContext();
      assertNull("Caller Principal is null", SecurityAssociation.getCallerPrincipal());
      
      //Create a security context with runas
      sc =  new JBossSecurityContext("TEST");
      
      @SuppressWarnings("unchecked")
      RunAs ras = new RunAs()
      { 
         public <T> T getIdentity()
         { 
            return (T) getName();
         }

         public <T> T getProof()
         { 
            return null;
         }

         public String getName()
         { 
            return "anil";
         }};
         
      sc.setIncomingRunAs(ras);
      SecurityContextAssociation.setSecurityContext(sc);
      assertEquals("CallerPrincipal=anil",p,SecurityAssociation.getCallerPrincipal()); 
   }
   
   public void testSetPrincipal()
   {
      assertNull("Principal is null", SecurityAssociation.getPrincipal());
      Principal p = new SimplePrincipal("anil");
      SecurityAssociation.setPrincipal(p);
      assertEquals("Principal=anil",p, SecurityAssociation.getPrincipal());
      
      //Check the SecurityContext also
      SecurityContext sc = getSecurityContext();
      assertEquals("Principal=anil","anil", sc.getUtil().getUserPrincipal().getName());
   }
   
   public void testSetCredential()
   {
      Object cred = new String("pass");
      assertNull("Credential is null", SecurityAssociation.getCredential()); 
      SecurityAssociation.setCredential(cred);
      assertEquals("Credential=pass",cred, SecurityAssociation.getCredential());
      
      //Check the SecurityContext also
      SecurityContext sc = getSecurityContext();
      assertEquals("cred=pass",cred, sc.getUtil().getCredential());
   }
   
   public void testPushPopRunAsIdentity()
   {
      assertNull("RunAsIdentity is null", SecurityAssociation.popRunAsIdentity());
      
      RunAsIdentity rai = new RunAsIdentity("role", "anil");
      SecurityAssociation.pushRunAsIdentity(rai);
      
      //Check the security context
      SecurityContext sc = getSecurityContext();
      assertEquals("RAI = anil,role", rai, sc.getOutgoingRunAs());
      assertEquals("RAI = anil,role", rai, SecurityAssociation.popRunAsIdentity());
      assertNull("RAI is null", sc.getOutgoingRunAs());  
   }
   
   /**
    * Validate that the SecurityAssociation.setPrincipal
    * usage on the server side creates a subject context
    * on the thread local subject context stack
    */
   public void testSetPrincipalSubjectStack()
   {
      SecurityAssociation.clear();
      SecurityAssociation.setServer();
      
      SubjectContext subjectContext = SecurityAssociation.peekSubjectContext();
      assertTrue("SubjectContext is null", subjectContext == null);
      
      //Direct Usage of setPrincipal on the server side will increase subject ctx
      SecurityAssociation.setPrincipal(null);
      subjectContext = SecurityAssociation.peekSubjectContext();
      assertTrue("SubjectContext is not null", subjectContext != null);
   }
   
   /**
    * SECURITY-459: {@code SecurityAssociation#getContextInfo(String)} 
    * should return what is there on the current security context
    * @throws Exception
    */
   public void testGetContextAPI() throws Exception
   {
      String contextKey = "SomeContextKey"; 
      assertNull("SecurityAssociation.getContextInfo should return null", SecurityAssociation.getContextInfo(contextKey));
      SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
      SecurityContextAssociation.setSecurityContext(sc);
      
      //Let us just put a principal object in the context map
      Principal somePrincipal = new SimplePrincipal("someprincipal");
      sc.getData().put(contextKey, somePrincipal);
      
      Object contextObject = SecurityAssociation.getContextInfo(contextKey);
      
      assertEquals("Context Object is the principal?", contextObject, somePrincipal); 
      assertEquals("Principal name matches", "someprincipal", ((Principal)contextObject).getName());
   }
   
   private void checkSA(boolean threaded)
   {
      SecurityAssociation.setPrincipal(new SimplePrincipal("Anil"));
      SecurityAssociation.setCredential("p".toCharArray());
      
      Principal p = null;
      Object cred = null;
      
      if(threaded)
      {
         //Check the security context
         SecurityContext sc = getSecurityContext();
         p = sc.getUtil().getUserPrincipal();
         cred = sc.getUtil().getCredential();
      }
      else
      {
         p = SecurityAssociation.getPrincipal();
         cred = SecurityAssociation.getCredential();
      }
      assertEquals("Principal=Anil","Anil", p.getName());
      assertEquals("Cred=p","p", new String((char[])cred));
   }
}