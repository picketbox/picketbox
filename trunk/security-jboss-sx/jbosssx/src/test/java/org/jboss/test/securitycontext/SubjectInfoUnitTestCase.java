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
package org.jboss.test.securitycontext;

import java.security.Principal;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;

//$Id$

/**
 *  SubjectInfo interface tests
 *  @author Anil.Saldhana@redhat.com
 *  @since  Feb 25, 2008 
 *  @version $Revision$
 */
public class SubjectInfoUnitTestCase extends TestCase
{
   public void testCreateSubjectInfo() throws Exception
   {
      Principal thePrincipal = new SimplePrincipal("Anil");
      
      Subject theSubject = new Subject();
      theSubject.getPrincipals().add(thePrincipal);
      SecurityContext sc = SecurityContextFactory.createSecurityContext("TEST");
      sc.getUtil().createSubjectInfo(thePrincipal, "pass", theSubject);
      
      assertEquals(thePrincipal, sc.getUtil().getUserPrincipal());
      assertEquals("pass", sc.getUtil().getCredential());
      assertEquals(theSubject, sc.getUtil().getSubject()); 
   } 
}