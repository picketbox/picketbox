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
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.Subject;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.modules.ejb.EJBXACMLPolicyModuleDelegate;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.javaee.SecurityRoleRef;
import org.jboss.security.plugins.JBossPolicyRegistration;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 * XACML integration tests for the EJB Layer
 *
 * @author Anil.Saldhana@redhat.com
 * @version $Revision$
 * @since May 8, 2007
 */
public class EJBXACMLUnitTestCase {
    private Principal p = new SimplePrincipal("scott");
    private String contextID = "web.jar";


    @Before
    public void setUp() throws Exception {
        setSecurityConfiguration();

    }

    @Ignore
    @Test
    public void testValidEJBPolicyContextHandler() throws Exception {
        EJBXACMLPolicyModuleDelegate pc = new EJBXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);
        EJBResource er = getEJBResource(policyRegistration);

        er.setPolicyContextID(contextID);
        int res = pc.authorize(er, new Subject(), getRoleGroup());
        assertEquals(AuthorizationContext.PERMIT, res);
    }

    @Test
    public void testInvalidEJBPolicyContextHandler() throws Exception {
        EJBXACMLPolicyModuleDelegate pc = new EJBXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);
        EJBResource er = getEJBResource(policyRegistration);

        er.setPolicyContextID(contextID);
        er.setPrincipal(new SimplePrincipal("baduser"));

        int res = pc.authorize(er, new Subject(), getRoleGroup());
        assertEquals(AuthorizationContext.DENY, res);
    }

    @Test
    public void testEJBContextIsCallerInRoleValid() throws Exception {
        EJBXACMLPolicyModuleDelegate pc = new EJBXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);
        EJBResource er = getEJBResource(policyRegistration);

        er.setPolicyContextID(contextID);
        er.setPrincipal(new SimplePrincipal("baduser"));
        er.add(ResourceKeys.ROLEREF_PERM_CHECK, true);
        er.add(ResourceKeys.ROLENAME, "employee");

        Set<SecurityRoleRef> roleRefSet = new HashSet<SecurityRoleRef>();
        roleRefSet.add(this.getSecurityRoleRef("employee", "ProjectUser"));
        er.setSecurityRoleReferences(roleRefSet);

        int res = pc.authorize(er, new Subject(), getRoleGroup());
        assertEquals(AuthorizationContext.PERMIT, res);
    }

    @Test
    public void testEJBContextIsCallerInRoleInvalid() throws Exception {
        EJBXACMLPolicyModuleDelegate pc = new EJBXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);
        EJBResource er = getEJBResource(policyRegistration);

        er.setPolicyContextID(contextID);
        er.setPrincipal(new SimplePrincipal("baduser"));
        er.add(ResourceKeys.ROLEREF_PERM_CHECK, true);
        er.add(ResourceKeys.ROLENAME, "employee");

        Set<SecurityRoleRef> roleRefSet = new HashSet<SecurityRoleRef>();
        roleRefSet.add(this.getSecurityRoleRef("employee", "baduser"));
        er.setSecurityRoleReferences(roleRefSet);

        int res = pc.authorize(er, new Subject(), getRoleGroup());
        assertEquals(AuthorizationContext.DENY, res);
    }

    /**
     * Test whether the EJBXACMLPolicyDelegate will permit calls to particular overloaded method
     * <p>
     * NOTE: the policy only provides success for <i> public void largeMethod( String a, int[] b, String[] c ) </i>
     *
     * @throws Exception
     */
    @Test
    @Ignore
    public void testEJBOverloadedMethodsSuccessCase() throws Exception {
        EJBXACMLPolicyModuleDelegate pc = new EJBXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);

        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put(ResourceKeys.POLICY_REGISTRATION, policyRegistration);

        EJBResource er = new EJBResource(map);
        er.setEjbName("StatelessSession");
        er.setEjbMethod(StatelessSession.class.getDeclaredMethod("largeMethod", new Class[]{String.class, int[].class,
                String[].class}));

        er.setPrincipal(p);

        er.setPolicyContextID(contextID);
        int res = pc.authorize(er, new Subject(), getRoleGroup());
        assertEquals(AuthorizationContext.PERMIT, res);
    }

    /**
     * Test whether the EJBXACMLPolicyDelegate will deny calls to particular overloaded methods
     * <p>
     * NOTE: the policy only provides success for <i> public void largeMethod( String a, int[] b, String[] c ) </i>
     *
     * @throws Exception
     */
    @Test
    public void testEJBOverloadedMethodsUnsuccessCase() throws Exception {
        EJBXACMLPolicyModuleDelegate pc = new EJBXACMLPolicyModuleDelegate();

        PolicyRegistration policyRegistration = new JBossPolicyRegistration();
        registerPolicy(policyRegistration);

        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put(ResourceKeys.POLICY_REGISTRATION, policyRegistration);

        EJBResource er = new EJBResource(map);
        er.setEjbName("StatelessSession");
        er.setEjbMethod(StatelessSession.class.getDeclaredMethod("largeMethod", new Class[]{String.class, int[].class}));

        er.setPrincipal(p);

        er.setPolicyContextID(contextID);
        int res = pc.authorize(er, new Subject(), getRoleGroup());
        assertEquals(AuthorizationContext.DENY, res);

        //Lets try the no-arg method
        er.setEjbMethod(StatelessSession.class.getDeclaredMethod("largeMethod", new Class[0]));
        res = pc.authorize(er, new Subject(), getRoleGroup());
        assertEquals(AuthorizationContext.DENY, res);
    }

    private EJBResource getEJBResource(PolicyRegistration policyRegistration) throws Exception {
        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put(ResourceKeys.POLICY_REGISTRATION, policyRegistration);

        EJBResource er = new EJBResource(map);
        er.setEjbName("StatelessSession");
        er.setEjbMethod(StatelessSession.class.getDeclaredMethod("echo", new Class[0]));
        er.setPrincipal(p);
        return er;
    }

    private void registerPolicy(PolicyRegistration policyRegistration) {
        String xacmlPolicyFile = "authorization/xacml/jboss-xacml-ejb-policy.xml";
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        InputStream is = cl.getResourceAsStream(xacmlPolicyFile);
        if (is == null) { throw new RuntimeException("Input stream is null"); }
        policyRegistration.registerPolicy(contextID, PolicyRegistration.XACML, is);
    }

    private RoleGroup getRoleGroup() {
        SimpleRoleGroup srg = new SimpleRoleGroup(SecurityConstants.ROLES_IDENTIFIER);
        srg.addRole(new SimpleRole("ProjectUser"));
        return srg;
    }

    private void setSecurityConfiguration() throws Exception {
        SecurityConfiguration.addApplicationPolicy(new ApplicationPolicy("other"));
    }

    private SecurityRoleRef getSecurityRoleRef(String roleName, String roleLink) {
        return new SecurityRoleRef(roleName, roleLink);
    }

    /**
     * A simple POJO whose methods we use reflectively
     */
    public class StatelessSession {
        public void echo() {
        }

        public void largeMethod() {
        }

        public void largeMethod(String a, int[] b) {
        }

        public void largeMethod(String a, int[] b, String[] c) {
        }
    }
}