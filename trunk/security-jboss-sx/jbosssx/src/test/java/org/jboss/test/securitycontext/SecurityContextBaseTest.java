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
 
import java.security.Principal;
import java.util.List;

import junit.framework.TestCase;

import org.jboss.security.SimplePrincipal;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AttributeMappingInfo;
import org.jboss.security.config.ModuleOption;
import org.jboss.security.config.RoleMappingInfo;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.mapping.MappingType;
import org.jboss.security.mapping.config.MappingModuleEntry;
import org.jboss.security.mapping.providers.DeploymentRolesMappingProvider;
import org.jboss.security.mapping.providers.attribute.DefaultAttributeMappingProvider;
import org.jboss.security.plugins.JBossSecurityContext;

//$Id$

/**
 *  Base test class with common methods
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Dec 26, 2006 
 *  @version $Revision$
 */
public class SecurityContextBaseTest extends TestCase
{ 
   protected Principal principal = new SimplePrincipal("anil");
   protected Object cred = "hello";
   protected String securityDomain = "other";
   
   private String roleMappingModule = DeploymentRolesMappingProvider.class.getName();
   private String attrMappingModule = DefaultAttributeMappingProvider.class.getName();
   
   public void testSecurityConfiguration()
   {
      ApplicationPolicy ap = createApplicationPolicy(securityDomain);
      SecurityConfiguration.addApplicationPolicy(ap);
      assertEquals(SecurityConfiguration.getApplicationPolicy(securityDomain), ap);
   }
   
   protected JBossSecurityContext getSC(String domain)
   {
      if(domain == null)
         domain = securityDomain;
      return new JBossSecurityContext(securityDomain);
   }
   
   protected ApplicationPolicy createApplicationPolicy(String domain)
   {
      ApplicationPolicy ap = new ApplicationPolicy(domain);
      ap.setMappingInfo(MappingType.ROLE.name(), createRoleMappingInfo(domain)); 
      ap.setMappingInfo(MappingType.ATTRIBUTE.name(), this.createAttributeMappingInfo(domain));
      return ap; 
   }
   
   protected ApplicationPolicy createApplicationPolicy(String domain, RoleMappingInfo rmi)
   {
      ApplicationPolicy ap = new ApplicationPolicy(domain);
      ap.setMappingInfo(MappingType.ROLE.name(), rmi); 
      return ap; 
   }
   
   protected RoleMappingInfo createRoleMappingInfo(String domain)
   { 
      RoleMappingInfo rmi = new RoleMappingInfo(domain);
      rmi.add(new MappingModuleEntry(this.roleMappingModule));
      return rmi;
   }
   
   protected AttributeMappingInfo createAttributeMappingInfo(String domain)
   { 
      AttributeMappingInfo rmi = new AttributeMappingInfo(domain);
      MappingModuleEntry mme = new MappingModuleEntry(this.attrMappingModule); 
      
      ModuleOption option = new ModuleOption("anil.email", "anil@test");
      mme.add(option);
      rmi.add(mme);
      return rmi;
   }
   
   protected RoleMappingInfo createRoleMappingInfo(String domain, List<String> moduleNames)
   {
      RoleMappingInfo rmi = new RoleMappingInfo(domain);
      for(String mod:moduleNames)
      { 
         rmi.add(new MappingModuleEntry(mod));
      }
      return rmi;
   }
}
