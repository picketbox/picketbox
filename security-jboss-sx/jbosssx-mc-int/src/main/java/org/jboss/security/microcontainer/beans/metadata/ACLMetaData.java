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
 * This class represents the {@code <acl>} configuration in an application policy and contains the acl (instance-based
 * authorization) metadata information extracted by the XB parser.
 * </p>
 * <p>
 * The following policy excerpt shows an example of {@code <acl>} configuration:
 * 
 * <pre>
 *  &lt;application-policy xmlns=&quot;urn:jboss:security-beans:1.0&quot; name=&quot;TestPolicy1&quot;&gt;
 *     &lt;authentication&gt;
 *        ...
 *     &lt;/authentication&gt;
 *     &lt;acl&gt;
 *        &lt;acl-module code=&quot;org.jboss.security.authz.ACLModule1&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;aclOption1&quot;&gt;acl1.value1&lt;/module-option&gt;
 *        &lt;/acl-module&gt;
 *        &lt;acl-module code=&quot;org.jboss.security.authz.ACLModule2&quot; flag=&quot;required&quot;&gt;
 *           &lt;module-option name=&quot;aclOption1&quot;&gt;acl2.value1&lt;/module-option&gt;
 *           &lt;module-option name=&quot;aclOption2&quot;&gt;acl2.value2&lt;/module-option&gt;
 *        &lt;/acl-module&gt;
 *     &lt;/acl&gt;
 *     ...
 *  &lt;/application-policy&gt;
 * </pre>
 * 
 * The metadata that results from the XB parsing is used by the microcontainer to create an instance of
 * {@code ACLPolicyBean} and inject this instance into the {@code ApplicationPolicyBean} that represents the application
 * policy as a whole.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class ACLMetaData extends BasePolicyMetaData
{

   /*
    * (non-Javadoc)
    * 
    * @see org.jboss.security.microcontainer.beans.metadata.BasePolicyMetaData#setModules(java.util.List)
    */
   @Override
   @XmlElement(name = "acl-module", type = FlaggedModuleMetaData.class)
   public void setModules(List<BaseModuleMetaData> modules)
   {
      super.modules = modules;
   }

}
