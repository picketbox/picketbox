/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.Attribute;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingType;


/**
 *  Test the various mapping providers
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Dec 26, 2006 
 *  @version $Revision$
 */
public class MappingContextTestCase extends SecurityContextBaseTest
{ 
   @SuppressWarnings("deprecation")
   public void testDeploymentRolesProvider()
   {
      SecurityConfiguration.addApplicationPolicy(createApplicationPolicy(securityDomain));
      SecurityContext sc= getSC(securityDomain);
      HashSet<String> hs = new HashSet<String>();
      hs.add("t1");
      hs.add("t2");
      
      HashMap<String,Object> rolesMap = new HashMap<String,Object>();
      rolesMap.put(principal.getName(), hs );
      
      HashMap<String,Object> map = new HashMap<String,Object>();
      map.put(SecurityConstants.PRINCIPAL_IDENTIFIER, principal);
      map.put(SecurityConstants.DEPLOYMENT_PRINCIPAL_ROLES_MAP, rolesMap);
      
      RoleGroup grp = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);
      grp.addRole(new SimpleRole("oldRole"));

      MappingContext<RoleGroup> mc = sc.getMappingManager().getMappingContext(RoleGroup.class);
      assertNotNull("Mapping Context is not null", mc);
      mc.performMapping(map, grp);
      
      grp = (RoleGroup) mc.getMappingResult().getMappedObject();
      
      assertFalse("oldRole does not exist", grp.containsRole(new SimpleRole("oldRole")));
      assertTrue("t1 exists?",grp.containsRole(new SimpleRole("t1")));
      assertTrue("t2 exists?",grp.containsRole(new SimpleRole("t2")));
   }
   
   public void testAttributeProvider()
   {
      SecurityConfiguration.addApplicationPolicy(createApplicationPolicy(securityDomain));
      SecurityContext sc= getSC(securityDomain);
      HashSet<String> hs = new HashSet<String>();
      hs.add("t1");
      hs.add("t2");
      
      HashMap<String,Object> rolesMap = new HashMap<String,Object>();
      rolesMap.put(principal.getName(), hs );
      
      HashMap<String,Object> map = new HashMap<String,Object>();
      map.put(SecurityConstants.PRINCIPAL_IDENTIFIER, principal); 
      
      List<Attribute<String>> attrList = new ArrayList<Attribute<String>>(); 

      MappingContext<List<Attribute<String>>> mc = sc.getMappingManager().getMappingContext(MappingType.ATTRIBUTE.name());
      assertNotNull("Mapping Context is not null", mc);
      mc.performMapping(map, attrList);
      
      attrList = (List<Attribute<String>>) mc.getMappingResult().getMappedObject();
      
      assertNotNull("Attribute List not null", attrList); 
      
      for(Attribute<?> att: attrList)
      {
         //Email address 
         if(Attribute.TYPE.EMAIL_ADDRESS.get().equals(att.getName()))
            assertEquals("anil@test", att.getValue());
      }
   }
}