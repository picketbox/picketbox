/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.security.microcontainer.beans.metadata;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlNsForm;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.jboss.beans.metadata.spi.BeanMetaData;
import org.jboss.beans.metadata.spi.BeanMetaDataFactory;
import org.jboss.xb.annotations.JBossXmlSchema;

/**
 * <p>
 * This class represents the top-level &lt;policy&gt; element of a security policy.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
@JBossXmlSchema(namespace = "urn:jboss:security-beans:1.0", elementFormDefault = XmlNsForm.QUALIFIED)
@XmlRootElement(name = "policy")
@XmlType(name = "policyType", propOrder = {"appPolicies"})
public class SecurityPolicyMetaData implements BeanMetaDataFactory
{

   /** the collection of application policy metadata. */
   private List<ApplicationPolicyMetaDataFactory> appPolicies;

   /**
    * <p>
    * Obtains the metadata of the application policies.
    * </p>
    * 
    * @return a {@code List} containing the metadata of the application policies.
    */
   public List<ApplicationPolicyMetaDataFactory> getAppPolicies()
   {
      return appPolicies;
   }

   /**
    * <p>
    * Sets the application policies metadata.
    * </p>
    * 
    * @param appPolicies a {@code List} containing the metadata to be set.
    */
   @XmlElement(name = "application-policy", type = ApplicationPolicyMetaDataFactory.class)
   public void setAppPolicies(List<ApplicationPolicyMetaDataFactory> appPolicies)
   {
      this.appPolicies = appPolicies;
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.beans.metadata.spi.BeanMetaDataFactory#getBeans()
    */
   public List<BeanMetaData> getBeans()
   {
      List<BeanMetaData> result = new ArrayList<BeanMetaData>();
      for (ApplicationPolicyMetaDataFactory factory : this.appPolicies)
         result.addAll(factory.getBeans());

      return result;
   }
}
