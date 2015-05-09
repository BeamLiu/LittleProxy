package org.littleshoot.proxy.extras;

import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.littleshoot.proxy.SslEngineSource;

/**
 * init ssl content using specified keyStore and trustStore
 */
public abstract class BaseSelfSignedSslEngineSource implements SslEngineSource {

	private static final String PROTOCOL = "TLS";

	private final boolean sendCerts;
	private KeyStore trustStore;
	private KeyStore keyStore;
	private String keyStorePassword;

	private SSLContext sslContext;

	protected BaseSelfSignedSslEngineSource(boolean sendCerts) {
		this.sendCerts = sendCerts;
	}

	protected void setKeyStore(KeyStore keyStore, String keyStorePassword) {
		this.keyStore = keyStore;
		this.keyStorePassword = keyStorePassword;
	}

	protected void setTrustStore(KeyStore trustStore) {
		this.trustStore = trustStore;
	}

	protected KeyStore getKeyStore() {
		return this.keyStore;
	}

	public SSLContext getSslContext() {
		if (sslContext == null) {
			initializeSSLContext();
		}
		return sslContext;
	}

	@Override
	public SSLEngine newSslEngine() {
		return getSslContext().createSSLEngine();
	}

	private void initializeSSLContext() {
		String algorithm = Security
				.getProperty("ssl.KeyManagerFactory.algorithm");
		if (algorithm == null) {
			algorithm = "SunX509";
		}

		try {
			// Set up key manager factory to use our key store
			final KeyManagerFactory kmf = KeyManagerFactory
					.getInstance(algorithm);
			kmf.init(keyStore, keyStorePassword == null
					? null
					: keyStorePassword.toCharArray());

			TrustManager[] trustManagers = null;
			if (trustStore != null) {
				// Set up a trust manager factory to use our key store
				TrustManagerFactory tmf = TrustManagerFactory
						.getInstance(algorithm);
				// use jdk default truststore if it is an empty keystore
				if (trustStore.size() == 0) {
					tmf.init((KeyStore) null);
				} else {
					// use the given trustStore
					tmf.init(trustStore);
				}
				trustManagers = tmf.getTrustManagers();
			} else {
				trustManagers = new TrustManager[]{new X509TrustManager() {
					// TrustManager that trusts all servers
					@Override
					public void checkClientTrusted(X509Certificate[] arg0,
							String arg1) throws CertificateException {
					}

					@Override
					public void checkServerTrusted(X509Certificate[] arg0,
							String arg1) throws CertificateException {
					}

					@Override
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}
				}};
			}

			KeyManager[] keyManagers = null;
			if (sendCerts) {
				keyManagers = kmf.getKeyManagers();
			} else {
				keyManagers = new KeyManager[0];
			}

			// Initialize the SSLContext to work with our key managers.
			sslContext = SSLContext.getInstance(PROTOCOL);
			sslContext.init(keyManagers, trustManagers, null);
		} catch (final Exception e) {
			throw new Error("Failed to initialize the server-side SSLContext",
					e);
		}
	}
}
