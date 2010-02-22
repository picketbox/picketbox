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
package org.picketbox.test.annotations;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;

import javax.security.auth.Subject;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.junit.Test;
import org.picketbox.plugins.PicketBoxProcessor;
import org.picketbox.test.pojos.SecurityMappingAnnotationRolePOJO;

/**
 * <p> Unit test the {@code PicketBoxProcessor} </p>
 * @author Anil.Saldhana@redhat.com
 * @since Feb 16, 2010
 */ 
public class PicketBoxProcessorUnitTestCase
{
   @Test
   public void testAPI() throws Exception
   {
      SecurityMappingAnnotationRolePOJO pojo = new SecurityMappingAnnotationRolePOJO();
      
      PicketBoxProcessor processor = new PicketBoxProcessor(); 
      processor.setSecurityInfo("anil", "pass");
      processor.process(pojo);
      
      Principal anil = new SimplePrincipal("anil");
      assertEquals("Principal == anil", anil, processor.getCallerPrincipal());
      Subject callerSubject = processor.getCallerSubject();
      assertNotNull("Subject is not null", callerSubject);
      assertTrue("Subject contains principal anil", callerSubject.getPrincipals().contains(anil));
      RoleGroup callerRoles = processor.getCallerRoles();
      assertTrue("InternalUser is a role", callerRoles.containsRole(new SimpleRole("InternalUser")));
      assertTrue("AuthorizedUser is a role", callerRoles.containsRole(new SimpleRole("AuthorizedUser")));
   }
}