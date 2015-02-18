/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat Middleware LLC, and individual contributors
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

package org.jboss.test.auth.certs;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.X509Certificate;

import junit.framework.Assert;

import org.jboss.security.CertificatePrincipal;
import org.jboss.security.auth.certs.SubjectCNMapping;
import org.junit.Test;

public class CertificateTestCase {

	public static String KEYSTOREFILE = "src/test/resources/keystore/keystore.jks";

	
	@Test
	public void testCorrectSubjectCNMapping() throws Exception {
		
		InputStream fis = new FileInputStream(KEYSTOREFILE);
		KeyStore ksout = KeyStore.getInstance("JCEKS");
		ksout.load(fis, "password".toCharArray());
		fis.close();
		fis = null;

		X509Certificate selfsigned2 = (X509Certificate) ksout
				.getCertificate("selfsigned2");
		Assert.assertEquals("X.509", selfsigned2.getType());
		CertificatePrincipal snidnm = new SubjectCNMapping();

		Principal p = snidnm.toPrincipal(new X509Certificate[] { selfsigned2 });

		// "If keystore changes please change test control"
		Assert.assertEquals("Picketbox, vault 2", p.getName());
	}
}
