package org.jboss.test.security.acl;

import java.util.Collection;

import org.jboss.security.acl.ACLEntry;
import org.jboss.security.acl.ACLPersistenceStrategy;
import org.jboss.security.acl.ACLRegistration;
import org.jboss.security.authorization.Resource;

/**
 * <p>
 * A simple implementation of {@code ACLRegistration} for tests purposes. It uses a {@code ACLPersistenceStrategy}
 * to persist/remove the {@code ACL}s upon registration/deregistration.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class TestACLRegistration implements ACLRegistration
{

   private final ACLPersistenceStrategy strategy;

   /**
    * <p>
    * Builds an instance of {@code TestACLRegistration}.
    * </p>
    * 
    * @param strategy   the {@code ACLPersistenceStrategy} to be used by this implementation.
    */
   public TestACLRegistration(ACLPersistenceStrategy strategy)
   {
      this.strategy = strategy;
   }

   /**
    * @see org.jboss.security.acl.ACLRegistration#deRegisterACL(org.jboss.security.authorization.Resource)
    */
   public void deRegisterACL(Resource resource)
   {
      this.strategy.removeACL(resource);
   }

   /**
    * @see org.jboss.security.acl.ACLRegistration#registerACL(org.jboss.security.authorization.Resource)
    */
   public void registerACL(Resource resource)
   {
      this.strategy.createACL(resource);
   }

   /**
    * @see org.jboss.security.acl.ACLRegistration#registerACL(org.jboss.security.authorization.Resource, java.util.Collection)
    */
   public void registerACL(Resource resource, Collection<ACLEntry> entries)
   {
      this.strategy.createACL(resource, entries);
   }

}
