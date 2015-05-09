package org.littleshoot.proxy;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;

import org.apache.http.conn.ssl.AbstractVerifier;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.littleshoot.proxy.extras.CASignedMitmManager;

/**
 * Tests the {@link CASignedMitmManager}, there is nothing different with the
 * {@link MitmProxyTest}, except the {@link MitmManager} instances are
 * different, beside the assertion are same, in this test case, it also verified
 * the certificates between client and proxy communication.
 */
public class CASignedMitmProxyTest extends MitmProxyTest {

	@Override
	public MitmManager getMitmManager() {
		return new CASignedMitmManager();
	}

	@Override
	protected SSLSocketFactory getSSLSocketFactory(final boolean isProxied)
			throws Exception {
		if (isProxied) {
			/*
			 * it is client to proxy case, need verify the certificate CN, and
			 * the certificates
			 */
			return getSSLSocketFactoryForCASignedCase();
		} else {
			/*
			 * client connect to server directly, need use default one which is
			 * accepting all self signed certificate without any host name
			 * verification
			 */
			return super.getSSLSocketFactory(isProxied);
		}
	}

	protected static SSLSocketFactory getSSLSocketFactoryForCASignedCase()
			throws NoSuchAlgorithmException, KeyManagementException,
			KeyStoreException, UnrecoverableKeyException {
		return new SSLSocketFactory(new TrustStrategy() {
			@Override
			public boolean isTrusted(X509Certificate[] chain, String authType)
					throws CertificateException {
				if (chain.length != 2) {
					throw new CertificateException(
							"expect 2 certificates in the chain");
				}
				JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(
						chain[0]);
				if (!"LittleProxyRoot".equals(getX500StringName(certHolder
						.getIssuer()))) {
					throw new CertificateException(
							"expect root certificate issuer <LittleProxyRoot>, but it is <"
									+ getX500StringName(certHolder.getIssuer())
									+ ">");
				}
				if (!"littleproxy".equals(getX500StringName(certHolder
						.getSubject()))) {
					throw new CertificateException(
							"expect root certificate CN <littleproxy>, but it is <"
									+ getX500StringName(certHolder.getSubject())
									+ ">");
				}

				JcaX509CertificateHolder rootHolder = new JcaX509CertificateHolder(
						chain[1]);
				if (!"LittleProxyRoot".equals(getX500StringName(rootHolder
						.getIssuer()))) {
					throw new CertificateException(
							"expect root certificate issuer <LittleProxyRoot>, but it is <"
									+ getX500StringName(rootHolder.getIssuer())
									+ ">");
				}
				if (!"LittleProxyRoot".equals(getX500StringName(rootHolder
						.getSubject()))) {
					throw new CertificateException(
							"expect root certificate CN <LittleProxyRoot>, but it is <"
									+ getX500StringName(rootHolder.getSubject())
									+ ">");
				}
				return true;
			}

			private String getX500StringName(X500Name x500name) {
				RDN cn = x500name.getRDNs(BCStyle.CN)[0];
				return IETFUtils.valueToString(cn.getFirst().getValue());
			}
		},
		/*
		 * Here is impossible to BrowserCompatHostnameVerifier, as the server
		 * certificate is using "littleproxy", in this test case, only verify
		 * that the proxy generated certificate CN should have the same name
		 * with the one from target server certificate
		 */
		new AbstractVerifier() {
			@Override
			public void verify(String host, String[] cns, String[] subjectAlts)
					throws SSLException {
				if (!(cns != null && cns.length > 0 && "littleproxy"
						.equals(cns[0]))) {
					throw new SSLException(
							"expect certificate cn <littleproxy>, but it is <"
									+ (cns != null && cns.length > 0
											? cns[0]
											: null) + ">");
				}
			}
		});
	}
}
