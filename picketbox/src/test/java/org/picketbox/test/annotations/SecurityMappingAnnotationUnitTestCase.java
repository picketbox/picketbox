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
package org.picketbox.test.annotations;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.annotation.Annotation;

import org.jboss.security.annotation.SecurityMapping;
import org.junit.Test;
import org.picketbox.test.pojos.SecurityMappingAnnotationPrincipalPOJO;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Feb 14, 2010
 */ 
public class SecurityMappingAnnotationUnitTestCase
{
   @Test
   public void testSecurityMapping()
   {   
      Class<?> clazz = SecurityMappingAnnotationPrincipalPOJO.class;
      Annotation[] annotations = clazz.getAnnotations();
      assertEquals("1 annotation", 1, annotations.length);  
      Annotation annotation = annotations[0]; 
      assertTrue(annotation instanceof SecurityMapping); 
      SecurityMapping sm = (SecurityMapping) annotation;
      assertEquals("PRINCIPAL", sm.type());
   } 
}