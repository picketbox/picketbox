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

import java.util.List;

import javax.xml.bind.annotation.XmlElement;

/**
 * <p>
 * This class represents the {@code <identity-trust>} configuration in an application policy and contains the
 * identity-trust metadata information extracted by the XB parser.
 * </p>
 * <p>
 * The following policy excerpt shows an example of {@code <identity-trust>} configuration:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        ...
 *     &lt;/authentication&gt;
 *     ...
 *     &lt;identity-trust&gt;
 *        &lt;trust-module code=&quot;org.jboss.security.trust.IdentityTrustModule&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;trustOption1&quot;&gt;trust.value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;trustOption2&quot;&gt;trust.value2&lt;/module-option&gt;
 *        &lt;/trust-module&gt;
 *     &lt;/identity-trust&gt;
 *  &lt;/application-policy&gt;
 * </pre>
 * 
 * The metadata that results from the XB parsing is used by the microcontainer to create an instance of
 * {@code IdentityTrustPolicyBean} and inject this instance into the {@code ApplicationPolicyBean} that represents the
 * application policy as a whole.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class IdentityTrustMetaData extends BasePolicyMetaData
{

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.metadata.BasePolicyMetaData#setModules(java.util.List)
    */
   @Override
   @XmlElement(name = "trust-module", type = FlaggedModuleMetaData.class)
   public void setModules(List<BaseModuleMetaData> modules)
   {
      super.modules = modules;
   }

}
