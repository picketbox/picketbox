package org.jboss.test.authorization.jacc;

import junit.framework.TestCase;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.jacc.DelegatingPolicy;
import org.jboss.security.jacc.JBossPolicyConfigurationFactory;
import org.junit.Assert;
import org.junit.Test;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.WebResourcePermission;
import java.security.Permission;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;

/**
 * This class tests the behavior of the PicketBox JACC policy implementation in scenarios that involve the usage of the
 * "any authenticated user" role, "**".
 */
public class JACCAuthorizationUnitTestCase extends TestCase {

    private static final String ANY_AUTHENTICATED_USER_ROLE = "**";

    /**
     * This test installs the PicketBox policy and registers a WebResourcePermission with the role "**" (any authenticated
     * user). It then performs a series of implies methods, checking the results. Any authenticated user should be able
     * to access the resource identified by the same pattern and HTTP methods as the registered WebResourcePermission
     * irrespective of the security roles associated with that user.
     *
     * @throws Exception if an error occurs while running the test.
     */
    @Test
    public void testAnyAuthenticatedUserRole() throws Exception {

        Policy policy = new DelegatingPolicy();
        Policy.setPolicy(policy);
        PolicyContext.setContextID("testcontext");

        PolicyConfiguration configuration =
            new JBossPolicyConfigurationFactory().getPolicyConfiguration("testcontext", true);
        // create a permission for a web resource using the role '**' (any authenticated user).
        Permission permission = new WebResourcePermission("/test", "GET,POST");
        configuration.addToRole(ANY_AUTHENTICATED_USER_ROLE, permission);
        configuration.commit();

        Principal[] roles = new Principal[]{new SimplePrincipal("Manager"), new SimplePrincipal("Administrator")};
        // should match - same pattern, same methods. Authenticated user has a couple of roles.
        boolean implies = policy.implies(new ProtectionDomain(null, null, null, roles),
                new WebResourcePermission("/test", "POST,GET"));
        Assert.assertTrue(implies);

        // should match - same pattern, same methods. User contains has no roles.
        implies = policy.implies(new ProtectionDomain(null, null, null, new Principal[]{}),
                new WebResourcePermission("/test", "POST,GET"));
        Assert.assertTrue(implies);

        // should not match - supplied permission has a different pattern.
        implies = policy.implies(new ProtectionDomain(null, null, null, roles),
                new WebResourcePermission("/test/*", "GET,POST"));
        Assert.assertFalse(implies);

        // should not match - supplied permission has a different list of methods.
        implies = policy.implies(new ProtectionDomain(null, null, null, roles),
                new WebResourcePermission("/test/*", "GET,DELETE,PUT"));
        Assert.assertFalse(implies);
    }
}
