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
package org.picketbox.test.api;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingManager;
import org.jboss.security.mapping.MappingType;
import org.picketbox.config.PicketBoxConfiguration;
import org.picketbox.factories.SecurityFactory;
import org.picketbox.util.PicketBoxUtil;

/**
 * Unit test the mapping framework
 * @author Anil.Saldhana@redhat.com
 * @since Feb 5, 2010
 */
public class MappingUnitTestCase extends TestCase
{
   /**
    * Test the Role Mapping Functionality
    */
   public void testRoleMapping()
   {
      String securityDomainName = "role-mapping-test";
      
      SecurityFactory.prepare();
      try
      {
         String configFile = "config/mapping.conf";
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(am);

         Subject subject = new Subject();
         Principal principal = new SimplePrincipal("anil");
         Object credential = new String("pass");

         boolean result = am.isValid(principal, credential); 
         assertTrue("Valid Auth", result);
         result = am.isValid(principal, credential, subject);
         assertTrue("Valid Auth", result);
         assertTrue("Subject has principals", subject.getPrincipals().size() > 0); 
         
         RoleGroup roles = PicketBoxUtil.getRolesFromSubject(subject);
         if(roles == null)
            throw new RuntimeException("Roles obtained from subject are null");
         
         //Lets do the role mapping now
         MappingManager mm = SecurityFactory.getMappingManager(securityDomainName);
         MappingContext<RoleGroup> mc = mm.getMappingContext(MappingType.ROLE.name());
         
         Map<String,Object> contextMap = new HashMap<String,Object>();
         
         mc.performMapping(contextMap, roles);
         RoleGroup mappedRoles = mc.getMappingResult().getMappedObject(); 
         assertNotNull(mappedRoles);
         //We added two extra roles to the role group
         assertEquals("3 roles", 3, mappedRoles.getRoles().size());
         assertTrue("Contains AuthorizedUser", mappedRoles.containsRole(new SimpleRole("AuthorizedUser")));
         assertTrue("Contains InternalUser", mappedRoles.containsRole(new SimpleRole("InternalUser")));
      }
      finally
      {
         SecurityFactory.release();
      }
   } 
   
   public void testPrincipalMapping()
   {
      String securityDomainName = "principal-mapping-test";
      
      SecurityFactory.prepare();
      try
      {
         String configFile = "config/mapping.conf";
         PicketBoxConfiguration idtrustConfig = new PicketBoxConfiguration();
         idtrustConfig.load(configFile);

         AuthenticationManager am = SecurityFactory.getAuthenticationManager(securityDomainName);
         assertNotNull(am);

         Subject subject = new Subject();
         Principal principal = new SimplePrincipal("anil");
         Object credential = new String("pass");

         boolean result = am.isValid(principal, credential); 
         assertTrue("Valid Auth", result);
         result = am.isValid(principal, credential, subject);
         assertTrue("Valid Auth", result);
         assertTrue("Subject has principals", subject.getPrincipals().size() > 0); 
          
         //Lets do the role mapping now
         MappingManager mm = SecurityFactory.getMappingManager(securityDomainName);
         MappingContext<Principal> mc = mm.getMappingContext(MappingType.PRINCIPAL.name());
         
         Map<String,Object> contextMap = new HashMap<String,Object>();
         
         mc.performMapping(contextMap, principal);
         Principal mappedPrincipal = mc.getMappingResult().getMappedObject(); 
        
         assertTrue("security-anil".equals(mappedPrincipal.getName()));
      }
      finally
      {
         SecurityFactory.release();
      }
   }
}