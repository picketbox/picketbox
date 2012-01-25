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
package org.jboss.test.security.securitycontext;

import java.security.Principal;
import java.security.acl.Group;
import java.util.Set;

import javax.security.auth.Subject;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory; 
import org.jboss.security.identity.Identity;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.fed.SAMLIdentity;

import junit.framework.TestCase;
 

/**
 *  SubjectInfo interface tests
 *  @author Anil.Saldhana@redhat.com
 *  @since  Feb 25, 2008 
 *  @version $Revision$
 */
public class SubjectInfoUnitTestCase extends TestCase
{
   private Identity identity = null;
   
   public void testCreateSubjectInfo() throws Exception
   {
      Principal thePrincipal = new Principal()
      {
         public String getName()
         {
            return "Anil";
         }
      };
      
      Subject theSubject = new Subject();
      theSubject.getPrincipals().add(thePrincipal);
      SecurityContext sc = SecurityContextFactory.createSecurityContext("TEST",
            TestSecurityContext.class.getCanonicalName());
      sc.getUtil().createSubjectInfo(thePrincipal, "pass", theSubject);
      
      assertEquals(thePrincipal, sc.getUtil().getUserPrincipal());
      assertEquals("pass", sc.getUtil().getCredential());
      assertEquals(theSubject, sc.getUtil().getSubject()); 
   }
   
   @SuppressWarnings("unchecked")
   public void testCreateFedIdentities() throws Exception 
   {
      SecurityContext sc = SecurityContextFactory.createSecurityContext("TEST",
            TestSecurityContext.class.getCanonicalName());
      
      sc.getUtil().createSubjectInfo(getIdentity(), null);  
      
      Set<Identity> iset = sc.getUtil().getIdentities(SAMLIdentity.class);
      assertEquals(1, iset.size());
      Identity id = iset.iterator().next();
      assertEquals(getIdentity(), id);
      assertTrue(id instanceof SAMLIdentity);
      assertTrue(((SAMLIdentity)id).getSAMLObject() instanceof FedIdentityObject);
   }
   
   private Identity getIdentity()
   {
      if(identity == null)
         identity = new SAMLIdentity<FedIdentityObject>()
      { 
         private static final long serialVersionUID = 1L;
         FedIdentityObject fio = new FedIdentityObject();

         public FedIdentityObject getSAMLObject()
         {
            return fio;
         }

         public void setSAMLObject(FedIdentityObject t)
         {
         }

         public Group asGroup()
         {
            return null;
         }

         public Principal asPrincipal()
         {
            return null;
         }

         public String getName()
         {
            return null;
         }

         public Role getRole()
         {
            return null;
         }
      };     
      
      return identity;
   }
}