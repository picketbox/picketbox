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
package org.jboss.test.authorization.xacml;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;
import java.security.Principal;
import java.util.HashMap;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.modules.web.WebXACMLPolicyModuleDelegate;
import org.jboss.security.authorization.resources.WebResource;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.plugins.JBossPolicyRegistration;
import org.jboss.test.SecurityActions;
import org.jboss.test.util.TestHttpServletRequest;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;


/**
 * XACML integration tests for the Web Layer
 *
 * @author Anil.Saldhana@redhat.com
 * @version $Revision$
 * @since May 8, 2007
 */
public class WebXACMLUnitTestCase {
    private Principal p = new SimplePrincipal("jduke");
    private String contextID = "web.jar";
    private String uri = "/xacml-subjectrole/test";

    @Before
    public void setUp() throws Exception {
        setSecurityContext();
        setSecurityConfiguration();
    }

    @Test
    @Ignore
    public void testValidWebPolicyContextHandler() throws Exception {
        WebXACMLPolicyModuleDelegate pc = new WebXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);
        WebResource er = getResource(policyRegistration);
        er.setPolicyContextID(this.contextID);

        er.setServletRequest(new TestHttpServletRequest(p, uri, "GET"));
        assertEquals(AuthorizationContext.PERMIT,
                pc.authorize(er, getSubject(), getRoleGroup()));

        Principal principal = new SimplePrincipal("Notjduke");
        HttpServletRequest hsr = new TestHttpServletRequest(principal, uri, "GET");
        //Now change the ejb principal
        er.setServletRequest(hsr);
        assertEquals(AuthorizationContext.DENY,
                pc.authorize(er, getSubject(), getRoleGroup()));
    }

    @Test
    public void testInvalidWebPolicyContextHandler() throws Exception {
        WebXACMLPolicyModuleDelegate pc = new WebXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);
        WebResource er = getResource(policyRegistration);
        er.setPolicyContextID(this.contextID);

        Principal principal = new SimplePrincipal("Notjduke");
        HttpServletRequest hsr = new TestHttpServletRequest(principal, uri, "GET");
        //Now change the ejb principal
        er.setServletRequest(hsr);
        assertEquals(AuthorizationContext.DENY,
                pc.authorize(er, getSubject(), getRoleGroup()));
    }

    private WebResource getResource(PolicyRegistration policyRegistration) {
        HashMap<String, Object> map = new HashMap<String, Object>();
        // map.put(ResourceKeys.WEB_REQUEST, new TestHttpServletRequest(p, uri, "GET"));
        map.put(ResourceKeys.POLICY_REGISTRATION, policyRegistration);
        return new WebResource(map);
    }

    private void registerPolicy(PolicyRegistration policyRegistration) {
        String xacmlPolicyFile = "authorization/xacml/jboss-xacml-web-policy.xml";
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        InputStream is = cl.getResourceAsStream(xacmlPolicyFile);
        if (is == null) { throw new RuntimeException("Input stream is null"); }
        policyRegistration.registerPolicy(contextID, PolicyRegistration.XACML, is);
    }

    private RoleGroup getRoleGroup() {
        SimpleRoleGroup srg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);
        srg.addRole(new SimpleRole("ServletUserRole"));
        return srg;
    }

    private Subject getSubject() {
        Subject subj = new Subject();
        SecurityActions.addPrincipalToSubject(subj, p);
        return subj;
    }

    private void setSecurityContext() {
        SecurityContext sc = null;
        try {
            sc = SecurityContextFactory.createSecurityContext("other");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        sc.getUtil().createSubjectInfo(p, "cred", getSubject());
        SecurityContextAssociation.setSecurityContext(sc);
    }

    private void setSecurityConfiguration() throws Exception {
        SecurityConfiguration.addApplicationPolicy(new ApplicationPolicy("other"));
    }
}
