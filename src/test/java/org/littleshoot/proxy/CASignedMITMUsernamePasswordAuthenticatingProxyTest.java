package org.littleshoot.proxy;

import static org.littleshoot.proxy.CASignedMitmProxyTest.getSSLSocketFactoryForCASignedCase;

import org.apache.http.conn.ssl.SSLSocketFactory;
import org.littleshoot.proxy.extras.CASignedMitmManager;
/**
 * Tests a single proxy that requires username/password authentication and that
 * uses MITM.
 */
public class CASignedMITMUsernamePasswordAuthenticatingProxyTest
		extends
			UsernamePasswordAuthenticatingProxyTest
		implements
			ProxyAuthenticator {
	@Override
	protected void setUp() {
		this.proxyServer = bootstrapProxy().withPort(0)
				.withProxyAuthenticator(this)
				.withManInTheMiddle(new CASignedMitmManager()).start();
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

	@Override
	protected boolean isMITM() {
		return true;
	}
}
