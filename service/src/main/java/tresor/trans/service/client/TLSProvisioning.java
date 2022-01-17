/****************************************************************************
 * Copyright (c) 2021 Federal Office for Information Security (BSI), ecsec GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/



package tresor.trans.service.client;
import de.bund.bsi.tr_esor.api._1_2.S4;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Optional;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tresor.trans.service.client.ClientConfig.TLSConfig;


/**
 *
 * @author Florian Otto
 */
public class TLSProvisioning {
	private static final Logger LOG = LoggerFactory.getLogger(TLSProvisioning.class);

	public static void configure(S4 client, TLSConfig config) throws TresorTransClientConfigException {
		try {
			final var httpConduit = (HTTPConduit) ClientProxy.getClient(client).getConduit();
			final var tlsClientParameters = Optional.ofNullable(httpConduit.getTlsClientParameters()).orElseGet(TLSClientParameters::new);
//			tlsClientParameters.setCertAlias(config.clientCert().keyAlias());
			tlsClientParameters.setKeyManagers(createKeyManager(config));
			tlsClientParameters.setTrustManagers(createTrustManager(config));
			httpConduit.setTlsClientParameters(tlsClientParameters);
		} catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {

			LOG.error("Error during starup", ex);
			throw new TresorTransClientConfigException(ex);
		}
	}

	private static KeyManager[] createKeyManager(TLSConfig config) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException {
		var kf = KeyManagerFactory.getInstance("PKIX");

		var ksFile = new File(config.keystoreFilepath());
		var ks = KeyStore.getInstance("PKCS12");
		InputStream ir = new FileInputStream(ksFile);
		ks.load(ir, config.keystoreSecret().toCharArray());

		kf.init(ks, config.keystoreSecret().toCharArray());

		return kf.getKeyManagers();
	}

	private static TrustManager[] createTrustManager(TLSConfig config) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		var tf = TrustManagerFactory.getInstance("PKIX");

		var ksFile = new File(config.truststoreFilepath());
		var ks = KeyStore.getInstance("JKS");
		InputStream ir = new FileInputStream(ksFile);
		ks.load(ir, null);

		tf.init(ks);

		return tf.getTrustManagers();
	}
}
