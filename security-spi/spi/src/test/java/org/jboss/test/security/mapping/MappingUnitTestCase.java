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
package org.jboss.test.security.mapping;

import java.security.acl.Group;

import javax.naming.InitialContext;
import javax.security.auth.x500.X500Principal;

import org.jboss.security.mapping.MappingType;

import junit.framework.TestCase;

/**
 * Test the mapping framework
 * @author Anil.Saldhana@redhat.com
 * @since Oct 13, 2008
 */
public class MappingUnitTestCase extends TestCase
{ 
   public void testMappingProviderSupportsMethod()
   {
      TestMappingProvider tmp = new TestMappingProvider();
      //Support Principal
      assertTrue(tmp.supports(X500Principal.class));
      //Do not support group principal
      assertFalse(tmp.supports(Group.class));
      //Do not support arbitrary JDK class
      assertFalse(tmp.supports(InitialContext.class));
      assertFalse(tmp.supports(MappingUnitTestCase.class));
   }
   
   public void testMappingType()
   {
      assertEquals("credential", MappingType.CREDENTIAL.toString());
      assertEquals("role", MappingType.ROLE.toString());
      assertEquals("principal", MappingType.PRINCIPAL.toString());
   }
}