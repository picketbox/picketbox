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

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.MappingInfo;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingManager;
import org.jboss.security.mapping.MappingType;
import org.jboss.security.mapping.config.MappingModuleEntry;
import org.jboss.security.mapping.providers.principal.SubjectDNMapper;

//$Id$

/**
 *  Tests the Principal Mapping layer
 *  @author Anil.Saldhana@redhat.com
 *  @since  Oct 5, 2007 
 *  @version $Revision$
 */
public class PrincipalMappingUnitTestCase extends TestCase
{
   protected void setUp() throws Exception
   {
      ApplicationPolicy ap = new ApplicationPolicy("test"); 
      SecurityConfiguration.addApplicationPolicy(ap);
   }
   
   public void testX509() throws Exception
   {  
      ApplicationPolicy ap = SecurityConfiguration.getApplicationPolicy("test"); 
      MappingModuleEntry mme = new MappingModuleEntry(SubjectDNMapper.class.getName());
      MappingInfo principalMappingInfo = new MappingInfo();
      principalMappingInfo.add(mme);
      ap.setMappingInfo(MappingType.PRINCIPAL.name(), principalMappingInfo);
     
      String issuerDN = "CN=Fedora,OU=JBoss,O=Red Hat,C=US";
      String subjectDN = "CN=Anil,OU=JBoss,O=Red Hat,C=US";
      

      Principal x509 = new SimplePrincipal("CN=Fedora, OU=JBoss, O=Red Hat, C=DE");
      
      SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
      MappingManager mm = sc.getMappingManager();
      assertNotNull("MappingManager != null", mm);
      MappingContext<Principal> mc = mm.getMappingContext(MappingType.PRINCIPAL.name());
      assertNotNull("MappingContext != null", mc);
      HashMap<String,Object> map = new HashMap<String,Object>();
     
      X509Certificate cert = getX509Certificate(issuerDN,subjectDN);
      X509Certificate[] certs = new X509Certificate[]{cert}; 
      map.put("X509", certs);
      mc.performMapping(map, x509);
      Principal mappedPrincipal = (Principal) mc.getMappingResult().getMappedObject(); 
      assertEquals(subjectDN,mappedPrincipal.getName());
   } 
   
   private X509Certificate getX509Certificate(String issuerDN, String subjectDN)
   {
      return new TestX509Certificate(new X500Principal(issuerDN),
                                     new X500Principal(subjectDN));
   }
}