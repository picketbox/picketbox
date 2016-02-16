/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
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

package org.jboss.test.security.mapping;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import javax.security.auth.login.Configuration;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextFactory;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.login.XMLLoginConfigImpl;
import org.jboss.security.config.ApplicationPolicy;
import org.jboss.security.config.SecurityConfiguration;
import org.jboss.security.config.parser.StaxBasedConfigParser;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRole;
import org.jboss.security.identity.plugins.SimpleRoleGroup;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingManager;
import org.jboss.security.mapping.MappingProvider;
import org.jboss.security.mapping.MappingType;
import org.jboss.test.security.ldap.OpenDSUnitTestsAdapter;

/**
 * @author Ryan Emerson
 */
public class LdapRoleMappingProviderTestCase extends OpenDSUnitTestsAdapter {

    public LdapRoleMappingProviderTestCase(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        super.setUp();
        XMLLoginConfigImpl xmlLogin = XMLLoginConfigImpl.getInstance();
        Configuration.setConfiguration(xmlLogin);

        ApplicationPolicy ap = new ApplicationPolicy("test");
        SecurityConfiguration.addApplicationPolicy(ap);

        String fileName = targetDir + "ldap" + fs + "ldapRoleMapping.ldif";
        boolean op = util.addLDIF(serverHost, port, adminDN, adminPW, new File(fileName).toURI().toURL());
        assertTrue(op);
    }

    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public void testRoleRecursion() throws Exception {
        StaxBasedConfigParser parser = new StaxBasedConfigParser();
        parser.parse(Thread.currentThread().getContextClassLoader().getResourceAsStream("ldap/ldap-role-mapping-config.xml"));

        SecurityContext sc = SecurityContextFactory.createSecurityContext("test");
        MappingManager mm = sc.getMappingManager();
        assertNotNull("MappingManager == null", mm);

        MappingContext<RoleGroup> mc = mm.getMappingContext(MappingType.ROLE.name());
        assertNotNull("MappingContext == null", mc);

        assertTrue(mc.hasModules());
        HashMap<String, Object> map = new HashMap<>();
        map.put(SecurityConstants.PRINCIPAL_IDENTIFIER, new SimplePrincipal("jduke"));
        MappingProvider<RoleGroup> provider = mc.getModules().get(0);
        RoleGroup roleGroup = new SimpleRoleGroup("roles");
        provider.performMapping(map, roleGroup);
        Collection<Role> roles = roleGroup.getRoles();

        assertEquals(roles.size(), 4);
        List<Role> correctRoles = new ArrayList<>();
        for (int i = 1; i < 5; i++)
            correctRoles.add(new SimpleRole("R"+i));
        assertTrue(roles.containsAll(correctRoles));
    }
}
