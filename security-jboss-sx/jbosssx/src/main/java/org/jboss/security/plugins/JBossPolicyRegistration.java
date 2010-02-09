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
package org.jboss.security.plugins;

import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.JAXBElement;

import org.jboss.logging.Logger;
import org.jboss.security.acl.ACL;
import org.jboss.security.acl.ACLImpl;
import org.jboss.security.acl.config.ACLConfiguration;
import org.jboss.security.acl.config.ACLConfigurationFactory;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.factories.PolicyFactory;
import org.jboss.security.xacml.interfaces.XACMLPolicy;

/**
 * Default implementation of Policy Registration interface
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Mar 31, 2008
 * @version $Revision$
 */
public class JBossPolicyRegistration implements PolicyRegistration, Serializable
{
   private static final long serialVersionUID = 1L;

   private static Logger log = Logger.getLogger(JBossPolicyRegistration.class);

   protected boolean trace = log.isTraceEnabled();

   private final Map<String, Set<XACMLPolicy>> contextIdToXACMLPolicy = new HashMap<String, Set<XACMLPolicy>>();

   /**
    * When the policy configuration file is registered, we directly store a copy of the JBossPDP that has read in the
    * config file
    */
   private final Map<String, JBossPDP> contextIDToJBossPDP = new HashMap<String, JBossPDP>();

   /** Map to keep track of the ACLs that have been configured in each context. */
   private final Map<String, Set<ACL>> contextIDToACLs = new HashMap<String, Set<ACL>>();

   /** Global map that keeps all the configured ACLs keyed by their resource */
   private final Map<String, ACL> configuredACLs = new HashMap<String, ACL>();

   public void deRegisterPolicy(String contextID, String type)
   {
      if (PolicyRegistration.XACML.equalsIgnoreCase(type))
      {
         this.contextIdToXACMLPolicy.remove(contextID);
         if (trace)
            log.trace("DeRegistered policy for contextId:" + contextID + ":type=" + type);
      }
      else if (PolicyRegistration.ACL.equalsIgnoreCase(type))
      {
         Set<ACL> acls = this.contextIDToACLs.remove(contextID);
         if (acls != null)
         {
            for (ACL acl : acls)
            {
               ACLImpl impl = (ACLImpl) acl;
               this.configuredACLs.remove(impl.getResourceAsString());
            }
         }
         if (trace)
            log.trace("Deregistered ACLs for contextId:" + contextID);
      }
   }

   @SuppressWarnings("unchecked")
   public <T> T getPolicy(String contextID, String type, Map<String, Object> contextMap)
   {
      if (PolicyRegistration.XACML.equalsIgnoreCase(type))
      {
         if (contextMap != null)
         {
            String pdp = (String) contextMap.get("PDP");
            if (pdp != null)
               return (T) this.contextIDToJBossPDP.get(contextID);
         }
         return (T) this.contextIdToXACMLPolicy.get(contextID);
      }
      else if (PolicyRegistration.ACL.equalsIgnoreCase(type))
      {
         if (contextMap != null)
         {
            String query = (String) contextMap.get("resource");
            if ("ALL".equalsIgnoreCase(query))
            {
               // return all the ACLs that have been registered.
               return (T) this.configuredACLs.values();
            }
            else if (query != null)
            {
               // we are looking for an ACL for an specific resource.
               return (T) this.configuredACLs.get(query);
            }
         }
         return (T) this.contextIDToACLs.get(contextID);
      }
      throw new RuntimeException("Unsupported type:" + type);
   }

   /**
    * @see PolicyRegistration#registerPolicy(String, String, URL)
    */
   public void registerPolicy(String contextID, String type, URL location)
   {
      try
      {
         if (trace)
            log.trace("Registering policy for contextId:" + contextID + " type: " + type + "and location:"
                  + location.getPath());
         registerPolicy(contextID, type, location.openStream());
      }
      catch (Exception e)
      {
         log.debug("Error in registering policy:", e);
      }
   }

   /**
    * @see PolicyRegistration#registerPolicy(String, String, InputStream)
    */
   public void registerPolicy(String contextID, String type, InputStream stream)
   {
      if (PolicyRegistration.XACML.equalsIgnoreCase(type))
      {
         try
         {
            XACMLPolicy policy = PolicyFactory.createPolicy(stream);

            Set<XACMLPolicy> policySet = this.contextIdToXACMLPolicy.get(contextID);
            if (policySet == null)
            {
               policySet = new HashSet<XACMLPolicy>();
            }
            policySet.add(policy);
            this.contextIdToXACMLPolicy.put(contextID, policySet);
         }
         catch (Exception e)
         {
            if(trace)
               log.debug("Error in registering xacml policy:", e);
         }
      }
      else if (PolicyRegistration.ACL.equalsIgnoreCase(type))
      {
         ACLConfiguration configuration = ACLConfigurationFactory.getConfiguration(stream);
         if(configuration == null)
            throw new IllegalStateException("ACL Configuration is null");
         Set<ACL> configuredACLs = configuration.getConfiguredACLs();
         // register the configured ACLs
         this.contextIDToACLs.put(contextID, configuredACLs);
         for (ACL acl : configuredACLs)
         {
            ACLImpl impl = (ACLImpl) acl;
            if (trace)
               log.trace("Registering ACL for resource " + impl.getResourceAsString());
            this.configuredACLs.put(impl.getResourceAsString(), acl);
         }
      }
   }

   /**
    * @see PolicyRegistration#registerPolicyConfig(String, String, Object)
    */
   public <P> void registerPolicyConfig(String contextId, String type, P objectModel)
   {
      if (PolicyRegistration.XACML.equalsIgnoreCase(type))
      {
         if(objectModel instanceof JAXBElement == false)
            throw new IllegalArgumentException("Unsupported model:" + objectModel);
         
         try
         {
            JAXBElement<?> jaxbModel = (JAXBElement<?>) objectModel;
            JBossPDP pdp = new JBossPDP(jaxbModel);
            this.contextIDToJBossPDP.put(contextId, pdp);
         }
         catch (Exception e)
         {
            throw new RuntimeException(e);
         }
      }
      else if (PolicyRegistration.ACL.equalsIgnoreCase(type))
      {
         if(objectModel instanceof ACLConfiguration == false)
            throw new IllegalArgumentException("Unsupported model:" + objectModel);
         
         ACLConfiguration configuration = (ACLConfiguration) objectModel;
         Set<ACL> configuredACLs = configuration.getConfiguredACLs();
         // register the configured ACLs
         this.contextIDToACLs.put(contextId, configuredACLs);
         for (ACL acl : configuredACLs)
         {
            ACLImpl impl = (ACLImpl) acl;
            if (trace)
               log.trace("Registering ACL for resource " + impl.getResourceAsString());
            this.configuredACLs.put(impl.getResourceAsString(), acl);
         }
      }
   }
   
   /**
    * @see PolicyRegistration#registerPolicyConfigFile(String, String, InputStream)
    */
   public void registerPolicyConfigFile(String contextId, String type, InputStream stream)
   {
      if (PolicyRegistration.XACML.equalsIgnoreCase(type))
      {
         try
         {
            JBossPDP pdp = new JBossPDP(stream);
            this.contextIDToJBossPDP.put(contextId, pdp);
         }
         catch (Exception e)
         {
            throw new RuntimeException(e);
         }
      }
   }
}