package org.littleshoot.proxy.extras;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500PrivateCredential;

import org.apache.commons.collections4.map.LRUMap;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.littleshoot.proxy.MitmManager;
import org.littleshoot.proxy.SslEngineSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link MitmManager} that uses CA signed certs for everything.
 * 
 * In some cases, if your LAN environment is already has a CA, and your
 * computers in the LAN environment already trusted this CA, then it will really
 * be helpful, those computers will trust the Mitm proxy generated certificates
 * which are signed by this CA, without promoting a certificate warning dialog.
 * If the CA keystore not specified, then it will generate a new CA keystore
 * first.
 */
public class CASignedMitmManager implements MitmManager {

	static {
		// add new provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	private static final Logger LOG = LoggerFactory
			.getLogger(CASignedMitmManager.class);
	private static SslEngineSource proxyToServerSslEngineSource;
	private final String PASSWORD = "password";
	private final String SELF_SIGNED_CA_CN = "LittleProxyRoot";
	private final ReentrantLock lock = new ReentrantLock();

	private String caKeyStorePath = System.getProperty("user.home")
			+ "/littleproxy_root.jks";
	private String caKeyStorePassword = PASSWORD;
	private String caKeyAlias = SELF_SIGNED_CA_CN;
	private String caKeyPassword = PASSWORD;
	private String caExportedCertificatePath = System.getProperty("user.home")
			+ "/littleproxy_root.cer";
	// a cache for generated certificates, key is the certificate CN
	private LRUMap<String, CASignedSslEngineSource> sslEngineSources = new LRUMap<String, CASignedSslEngineSource>(
			300);

	private Key caPrivateKey;
	private Certificate[] caCertChain;

	/**
	 * use default CA and trust all servers
	 */
	public CASignedMitmManager() {
		initCAInfo(true);
	}

	/**
	 * use default CA and verify remote server using given trustStore, if
	 * trustStore is null, use JDK default trustStore
	 */
	public CASignedMitmManager(final KeyStore trustStore) {
		initCAInfo(true);
		proxyToServerSslEngineSource = new ProxyToServersSslEngineSource(
				trustStore);
	}

	// use an existing CA keystore
	public CASignedMitmManager(String caKeyStorePath,
			String caKeyStorePassword, String caKeyAlias, String caKeyPassword) {
		this.caKeyStorePath = caKeyStorePath;
		this.caKeyStorePassword = caKeyStorePassword;
		this.caKeyAlias = caKeyAlias;
		this.caKeyPassword = caKeyPassword;
		initCAInfo(false);
	}

	@Override
	public SSLEngine serverSslEngine() {
		if (proxyToServerSslEngineSource == null) {
			proxyToServerSslEngineSource = new ProxyToServersSslEngineSource();
		}
		return proxyToServerSslEngineSource.newSslEngine();
	}

	@Override
	public SSLEngine clientSslEngineFor(SSLSession serverSslSession) {
		try {
			Certificate[] peerCerts = serverSslSession.getPeerCertificates();
			/*
			 * get the first certificate from the certificate chain, and the CN
			 * should be the target server domain
			 */
			String domain = getCNFromX509Certificate((X509Certificate) peerCerts[0]);
			/*
			 * there may be a concurrent request for a same domain, make sure
			 * one same keystore would be generated for the same domain
			 */
			lock.lock();
			CASignedSslEngineSource sslEngineSource = null;
			try {
				// find the CASignedSslEngineSource from cache
				sslEngineSource = sslEngineSources.get(domain);
				if (sslEngineSource == null) {
					sslEngineSource = new CASignedSslEngineSource(domain,
							caPrivateKey, caCertChain);
					sslEngineSources.put(domain, sslEngineSource);
				}
			} finally {
				lock.unlock();
			}
			return sslEngineSource.newSslEngine();
		} catch (Exception e) {
			throw new RuntimeException(
					"cannot generate certificates for a ssl session", e);
		}
	}

	private String getCNFromX509Certificate(X509Certificate cert)
			throws CertificateEncodingException {
		X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
		RDN cn = x500name.getRDNs(BCStyle.CN)[0];
		return IETFUtils.valueToString(cn.getFirst().getValue());
	}

	private void initCAInfo(boolean createSelfSignedCA) {
		try {

			if (new File(caKeyStorePath).exists()) {
				LOG.info("CA keystore already exists at " + caKeyStorePath);
			} else if (createSelfSignedCA) {
				LOG.info("Generating a new CA keystore");
				newRootKeyStore();
			} else {
				throw new Exception("cannot find CA keystore " + caKeyStorePath);
			}
			// restore CA information from keystore
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(
					new FileInputStream(caKeyStorePath),
					caKeyStorePassword == null ? null : caKeyStorePassword
							.toCharArray());
			caPrivateKey = keyStore.getKey(caKeyAlias, caKeyPassword == null
					? null
					: caKeyPassword.toCharArray());
			caCertChain = keyStore.getCertificateChain(caKeyAlias);
		} catch (Exception e) {
			throw new Error("Failed to initialize the server-side SSLContext",
					e);
		}
	}

	/*
	 * generate the root key store which contains the CA private key and public
	 * certificate
	 */
	private void newRootKeyStore() throws Exception {
		KeyPair keyPair = newRSAKeyPair();
		X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
				new X500Name("CN=" + SELF_SIGNED_CA_CN), new BigInteger(32,
						new SecureRandom()), new Date(), DateUtils.addDays(
						new Date(), 3 * 365), new X500Name("CN="
						+ SELF_SIGNED_CA_CN), keyPair.getPublic());
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider("BC").build(keyPair.getPrivate());
		X509Certificate cert = new JcaX509CertificateConverter().setProvider(
				"BC").getCertificate(certBldr.build(signer));
		// save self signed CA keyStore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		X500PrivateCredential credential = new X500PrivateCredential(cert,
				keyPair.getPrivate(), caKeyAlias);
		keyStore.setKeyEntry(credential.getAlias(), credential.getPrivateKey(),
				caKeyStorePassword.toCharArray(), new Certificate[]{cert});
		keyStore.store(new FileOutputStream(caKeyStorePath),
				caKeyStorePassword.toCharArray());
		LOG.info("CA keystore is generated successfully in " + caKeyStorePath);
		/*
		 * dump the certificate to a file, to make sure it is easy to install to
		 * client environment, of course, even those certificate is lost in the
		 * future, it also could be exported from the keystore using keytool
		 * which is embeded in JDK
		 */
		dumpCertFromKeyStore(cert, System.getProperty("user.home")
				+ "/littleproxy_root.cer");
		LOG.info("dumpped a CA certificate copy to "
				+ caExportedCertificatePath);
		// dump a copy to current running folder
		dumpCertFromKeyStore(cert, "littleproxy_root.cer");
	}

	/*
	 * dump certificate to a cer file, to make sure it is easy to install to
	 * client environment
	 */
	private void dumpCertFromKeyStore(X509Certificate cert, String path)
			throws CertificateEncodingException, IOException {
		FileOutputStream fos = new FileOutputStream(path);
		fos.write(cert.getEncoded());
		fos.flush();
		fos.close();
	}

	private KeyPair newRSAKeyPair() throws NoSuchAlgorithmException,
			NoSuchProviderException {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}

	static class ProxyToServersSslEngineSource
			extends
				BaseSelfSignedSslEngineSource {
		protected ProxyToServersSslEngineSource() {
			// not specify the trustStore, will trust all
			super(true);
			LOG.info("use turst all server truststore");
		}

		protected ProxyToServersSslEngineSource(KeyStore trustStore) {
			super(true);
			if (trustStore == null) {
				LOG.info("try to use JDK default trustStore");
				try {
					trustStore = KeyStore.getInstance("JKS");
					trustStore.load(null, null);
				} catch (Exception e) {
					throw new RuntimeException(
							"cannot initialize a truststore", e);
				}
			} else {
				LOG.info("use external truststore");
			}
			setTrustStore(trustStore);
		}
	}
}
