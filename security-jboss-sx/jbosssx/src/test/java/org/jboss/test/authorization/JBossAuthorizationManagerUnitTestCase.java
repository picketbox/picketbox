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
package org.jboss.test.authorization;

import java.security.Principal;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;

import junit.framework.TestCase;

import org.jboss.security.AuthorizationManager;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.authorization.config.AuthorizationModuleEntry;
import org.jboss.security.authorization.resources.WebResource;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.AuthorizationInfo;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.jacc.SubjectPolicyContextHandler;
import org.jboss.security.plugins.JBossAuthorizationManager;
import org.jboss.test.util.TestHttpServletRequest;

//$Id$

/**
 *  Unit test the JBossAuthorizationManager
 *  @author Anil.Saldhana@redhat.com
 *  @since  May 17, 2007 
 *  @version $Revision$
 */
public class JBossAuthorizationManagerUnitTestCase extends TestCase
{
   private Principal p = new SimplePrincipal("jduke");
   private String contextID = "web.war"; 
   
   protected void setUp() throws Exception
   { 
      super.setUp();
      setSecurityContext();
      setUpPolicyContext();
      setSecurityConfiguration();
   }
   
   public void testAuthorization() throws Exception
   {
      HashMap<String,Object> cmap = new HashMap<String,Object>(); 
      WebResource wr = new WebResource(cmap);
      wr.setServletRequest(new TestHttpServletRequest(p,"test", "get"));
      AuthorizationManager am = new JBossAuthorizationManager("other");
      am.authorize(wr);//This should just pass as the default module PERMITS all
   }
   
   private RoleGroup getRoleGroup()
   {
      RoleGroup rg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);
      rg.addRole(new SimpleRole("ServletUserRole"));
      return rg;
   }
   
   private void setSecurityContext() throws Exception
   { 
      Subject subj = new Subject();
      subj.getPrincipals().add(p);
      SecurityContext sc = SecurityContextFactory.createSecurityContext("other");
      sc.getUtil().createSubjectInfo(p, "cred", subj);
      sc.getUtil().setRoles(getRoleGroup());
      SecurityContextAssociation.setSecurityContext(sc);
   }
   
   private void setUpPolicyContext() throws Exception
   {
      PolicyContext.setContextID(contextID);
      PolicyContext.registerHandler(SecurityConstants.SUBJECT_CONTEXT_KEY, 
            new SubjectPolicyContextHandler(), true);
   }
   
   private void setSecurityConfiguration() throws Exception
   {
      String name = "org.jboss.security.authorization.modules.web.WebAuthorizationModule";
      ApplicationPolicy ap = new ApplicationPolicy("other");
      AuthorizationInfo ai = new AuthorizationInfo("other");
      AuthorizationModuleEntry ame = new AuthorizationModuleEntry(name);
      ai.add(ame);
      ap.setAuthorizationInfo(ai);
      SecurityConfiguration.addApplicationPolicy(ap); 
   } 
}
