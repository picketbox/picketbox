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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;

import javax.security.auth.Subject;

import org.jboss.security.AuthenticationManager;
import org.jboss.security.AuthorizationManager;
import org.jboss.security.ISecurityManagement;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.audit.AuditManager;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.identitytrust.IdentityTrustManager;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.providers.DeploymentRolesMappingProvider;
import org.jboss.security.plugins.JBossSecurityContext;
import org.jboss.security.plugins.JBossSecurityContextUtil;


/**
 *  Test the Security Context
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Dec 26, 2006 
 *  @version $Revision$
 */
public class SecurityContextTestCase extends SecurityContextBaseTest
{
   public void setUp()
   { 
      SecurityConfiguration.addApplicationPolicy(createApplicationPolicy(securityDomain));
   }
   
   public void testSecurityDomain()
   { 
      assertEquals("Security Domain == other", getSC(securityDomain).getSecurityDomain()
            ,securityDomain);
   }
   
   public void testSubjectInfo()
   {
      Subject sub = new Subject(); 
      
      JBossSecurityContext sc = getSC(securityDomain);
      assertNotNull("SubjectInfo is not null", sc.getSubjectInfo());
      sc.getUtil().createSubjectInfo(principal, cred, sub); 
       
      assertEquals("Subject is equal",sc.getSubjectInfo().getAuthenticatedSubject(),sub);
      assertEquals("Principal is equal",sc.getUtil().getUserPrincipal(),principal);
      assertEquals("Credential is equal",sc.getUtil().getCredential(),cred);
   } 
   
   public void testMappingContext()
   {   
      JBossSecurityContext sc = getSC(securityDomain);
      ISecurityManagement ism = sc.getSecurityManagement();
      assertNotNull("Security Management is not null", ism);
      MappingContext<RoleGroup> mc = sc.getMappingManager().getMappingContext("role");
      assertNotNull("Mapping Context is not null", mc); 
      List<?> modules = mc.getModules();
      assertNotNull("Mapping modules not null", modules);
      assertEquals("Module size == 1", modules.size(),1);
      assertTrue("Deployment Roles Provider is present", 
            modules.get(0) instanceof DeploymentRolesMappingProvider);
   }
   
   public void testSecurityContextFactory() throws Exception
   {
      SecurityContext sc = SecurityContextFactory.createSecurityContext(securityDomain);
      assertTrue("Instance of JBossSecurityContext", sc instanceof JBossSecurityContext);
      assertTrue("Instance of JBossSecurityContextUtil", sc.getUtil() instanceof JBossSecurityContextUtil);
      
      //Create an instance of TestSecurityContext
      sc = SecurityContextFactory.createSecurityContext(securityDomain, 
            TestSecurityContext.class.getName());
      assertTrue("Instance of TestSecurityContext", sc instanceof TestSecurityContext);      
   } 
   
   public void testManagersFromJBossSecurityContext() throws Exception
   { 
      JBossSecurityContext sc = this.getSC("other");
      ISecurityManagement ism = sc.getSecurityManagement();
      assertNotNull("Security Management is not null", ism);
      AuthenticationManager authManager = sc.getAuthenticationManager();
      assertNotNull("AuthenticationManager is not null", authManager);
      AuthorizationManager authorizationMgr = sc.getAuthorizationManager();
      assertNotNull("AuthorizationManager is not null", authorizationMgr);
      AuditManager auditManager = sc.getAuditManager();
      assertNotNull("AuditManager is not null", auditManager);
      IdentityTrustManager itm = sc.getIdentityTrustManager();
      assertNotNull("IdentityTrustManager is not null", itm);
   }
   
   public void testRoles()
   {
      JBossSecurityContext sc = this.getSC("other");
      SimpleRoleGroup roleGroup = new SimpleRoleGroup("Roles");
      roleGroup.addRole(new SimpleRole("testRole"));
      sc.getUtil().setRoles(roleGroup);
      
      //Retrieve the roles
      RoleGroup scRoles = sc.getUtil().getRoles();
      assertNotNull(scRoles);
      assertTrue(scRoles.containsAll(new SimpleRole("testRole")));
   }
   
   //Validates JBossSecurityContext is serializable
   public void testJBossSecurityContextSerialization() throws Exception
   { 
      JBossSecurityContext jsc = new JBossSecurityContext("other");
      
      // Serialize to a byte array
      ByteArrayOutputStream bos = new ByteArrayOutputStream() ;
      ObjectOutputStream out = new ObjectOutputStream(bos) ;
      out.writeObject(jsc);
      out.close();
     
      //Deserialize from a byte array
      JBossSecurityContext otherSC = null;
      ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()));
      otherSC = (JBossSecurityContext) in.readObject();
      in.close();
      assertNotNull("The deserialized security context is not null:", otherSC);
      assertEquals("other", otherSC.getSecurityDomain());
   }
}