package org.jboss.test.auth.certs;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import junit.framework.Assert;

import org.jboss.security.CertificatePrincipal;
import org.jboss.security.auth.certs.SerialNumberIssuerDNMapping;
import org.jboss.security.auth.certs.SubjectCNMapping;
import org.jboss.security.auth.certs.SubjectCNMappingFixed;
import org.jboss.security.auth.certs.SubjectDNMapping;
import org.jboss.security.auth.certs.SubjectX500Principal;
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

		ksout = null;
	}
}
