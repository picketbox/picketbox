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
package org.jboss.test.security.mapping;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import junit.framework.TestCase;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.mapping.MappingResult;
import org.jboss.security.mapping.providers.DeploymentRolesMappingProvider;

//$Id$

/**
 *  Unit test the DeploymentRolesMappingProvider
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jan 14, 2008 
 *  @version $Revision$
 */
public class DeploymentRolesMappingUnitTestCase extends TestCase
{
   public void testMappingWithPrincipal()
   {
      Map<String,Object> cmap = new HashMap<String,Object>();
     
      cmap.put(SecurityConstants.PRINCIPAL_IDENTIFIER, new SimplePrincipal("anil"));
      cmap.put(SecurityConstants.DEPLOYMENT_PRINCIPAL_ROLES_MAP, getPrincipalRoleMap());
      
      assertTrue(containsMapping(cmap));
   }
   
   public void testMappingWithPrincipalSet()
   {  
      Map<String,Object> cmap = new HashMap<String,Object>();
      Subject subject = new Subject();
      subject.getPrincipals().add(new SimplePrincipal("anil"));
     
      cmap.put(SecurityConstants.PRINCIPALS_SET_IDENTIFIER, subject.getPrincipals());
      cmap.put(SecurityConstants.DEPLOYMENT_PRINCIPAL_ROLES_MAP, getPrincipalRoleMap());
       
      assertTrue(containsMapping(cmap));
   }
   
   public void testUnsuccessfulMappingWithPrincipal()
   {
      Map<String,Object> cmap = new HashMap<String,Object>(); 
      cmap.put(SecurityConstants.PRINCIPAL_IDENTIFIER, new SimplePrincipal("impostor"));
      cmap.put(SecurityConstants.DEPLOYMENT_PRINCIPAL_ROLES_MAP, getPrincipalRoleMap());
      
      assertFalse(containsMapping(cmap));
   }
   
   public void testUnsuccessfulMappingWithPrincipalSet()
   {  
      Map<String,Object> cmap = new HashMap<String,Object>();
      Subject subject = new Subject();
      subject.getPrincipals().add(new SimplePrincipal("impostor"));
     
      cmap.put(SecurityConstants.PRINCIPALS_SET_IDENTIFIER, subject.getPrincipals());
      cmap.put(SecurityConstants.DEPLOYMENT_PRINCIPAL_ROLES_MAP, getPrincipalRoleMap());
       
      assertFalse(containsMapping(cmap));
   }
   
   private boolean containsMapping(Map<String,Object> cmap)
   {
      DeploymentRolesMappingProvider drmp = new DeploymentRolesMappingProvider();
      MappingResult<RoleGroup> result = new MappingResult<RoleGroup>();
      //MappingResult<Group> result = new MappingResult<Group>();
      drmp.setMappingResult(result);
      
      drmp.performMapping(cmap, getGroup(new String[]{"gooduser","okuser"}));
      return result.getMappedObject().containsRole(new SimpleRole("allowedUser"));
      //return result.getMappedObject().isMember(new SimplePrincipal("allowedUser")); 
   }
   
   private Map<String,Set<String>> getPrincipalRoleMap()
   {
      Map<String,Set<String>> pmap = new HashMap<String,Set<String>>();
      
      Set<String> roleSet = new HashSet<String>();
      String[] rolearr = {"allowedUser"}; 
      roleSet.addAll(Arrays.asList(rolearr));
      pmap.put("anil", roleSet);
      return pmap;
   }
   
   private RoleGroup getGroup(String[] principalArr)
   {
      RoleGroup rg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);
      for(String p: principalArr)
      {
         rg.addRole(new SimpleRole(p));
      } 
      return rg;
   }

}