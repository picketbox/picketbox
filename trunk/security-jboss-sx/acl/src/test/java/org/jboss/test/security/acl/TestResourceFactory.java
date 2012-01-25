package org.jboss.test.security.acl;

import org.jboss.security.acl.ACLResourceFactory;
import org.jboss.security.authorization.Resource;

public class TestResourceFactory implements ACLResourceFactory
{

   public Resource instantiateResource(String resourceClassName, Object id)
   {
      if (resourceClassName != null && resourceClassName.equals("org.jboss.test.security.acl.TestResource"))
      {
         int resourceId = Integer.parseInt((String) id);
         TestResource resource = new TestResource(resourceId);
         return resource;
      }

      return null;
   }
}
