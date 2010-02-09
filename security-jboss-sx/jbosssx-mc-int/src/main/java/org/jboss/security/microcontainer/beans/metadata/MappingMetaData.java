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
 * This class represents a {@code <rolemapping>} or a {@code <mapping>} configuration in an application policy and
 * contains the mapping metadata information extracted by the XB parser.
 * </p>
 * <p>
 * The following policy excerpt shows an example of {@code <rolemapping>} configuration:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        ...
 *     &lt;/authentication&gt;
 *     ...
 *     &lt;rolemapping&gt;
 *        &lt;mapping-module code=&quot;org.jboss.security.mapping.RoleMappingModule&quot;&gt;
 *           &lt;module-option name=&quot;mappingOption1&quot;&gt;mapping.value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;mappingOption2&quot;&gt;mapping.value2&lt;/module-option&gt;
 *        &lt;/mapping-module&gt;
 *     &lt;/rolemapping&gt;
 *     ...
 *  &lt;/application-policy&gt;
 * </pre>
 * 
 * Now an example of a {@code <mapping>} configuration:
 *
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        ...
 *     &lt;/authentication&gt;
 *     ...
 *     &lt;mapping&gt;
 *        &lt;mapping-module code=&quot;org.jboss.security.mapping.RoleMappingModule&quot; type=&quot;role&quot;&gt;
 *           &lt;module-option name=&quot;mappingOption1&quot;&gt;mapping.value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;mappingOption2&quot;&gt;mapping.value2&lt;/module-option&gt;
 *        &lt;/mapping-module&gt;
 *     &lt;/mapping&gt;
 *     ...
 *  &lt;/application-policy&gt;
 * </pre>
 * 
 * As can be noticed, both configurations are very similar. As a matter of fact, any module in a {@code <rolemapping>}
 * configuration is actually registered as a {@code <mapping>} module of type {@code "role"}.
 * 
 * The metadata that results from the XB parsing is used by the microcontainer to create an instance of
 * {@code IdentityTrustPolicyBean} and inject this instance into the {@code ApplicationPolicyBean} that represents the
 * application policy as a whole.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class MappingMetaData extends BasePolicyMetaData
{

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.metadata.BasePolicyMetaData#setModules(java.util.List)
    */
   @Override
   @XmlElement(name = "mapping-module", type = MappingModuleMetaData.class)
   public void setModules(List<BaseModuleMetaData> modules)
   {
      super.modules = modules;
   }

}
