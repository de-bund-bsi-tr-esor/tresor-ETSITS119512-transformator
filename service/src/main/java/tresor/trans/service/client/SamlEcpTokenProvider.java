/****************************************************************************
 * Copyright (c) 2020 Federal Office for Information Security (BSI), ecsec GmbH
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

import tresor.trans.service.S4ClientConfig;
import com.typesafe.config.ConfigBeanFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Tobias Wich
 */
@ApplicationScoped
public class SamlEcpTokenProvider {

	private final Logger LOG = LoggerFactory.getLogger(SamlEcpTokenProvider.class);

	@Inject
	S4ClientConfig config;

	private SamlEcpTokenConfig pConfig;

	private Instant fetchedAt;
	private String token;

	private SamlEcpTokenConfig getEcpTokenConfig() {
		synchronized (this) {
			if (pConfig == null) {
				pConfig = ConfigBeanFactory.create(config.getTypeSpecific(), SamlEcpTokenConfig.class);
			}
		}
		return pConfig;
	}

	public String getToken() {
		synchronized (this) {
			// if we have no token or the validity is expired
			if (fetchedAt == null || fetchedAt.plus(getEcpTokenConfig().getTokenValidity()).isBefore(Instant.now())) {
				token = getNewToken();
				fetchedAt = Instant.now();
			}
		}

		return token;
	}

	private String getNewToken() {
		LOG.info("Retrieving new token from SAML IdP.");
		SamlEcpTokenConfig procCfg = getEcpTokenConfig();
		Client c = ClientBuilder.newClient();

		try {
			String authnReq = performAuthnReq(procCfg, c);
			String authnRes = performEcpAuth(procCfg, c, authnReq);
			String newToken = performAcsReq(procCfg, c, authnRes);

			return newToken;
		} catch (WebApplicationException | ProcessingException ex) {
			LOG.error("Failed to retrieve token from SAML IdP.", ex);
			// TODO: explicit error handling
			throw ex;
		}
	}

	private String performAuthnReq(SamlEcpTokenConfig procCfg, Client c) throws WebApplicationException, ProcessingException {
		LOG.debug("Requesting SAML AuthnRequest.");
		String samlReq = c.target(URI.create(procCfg.getAuthnUrl()))
				.request()
				.accept("application/vnd.paos+xml")
				.get(String.class);
		return samlReq;
	}

	private String performEcpAuth(SamlEcpTokenConfig procCfg, Client c, String authnReq) throws WebApplicationException, ProcessingException {
		LOG.debug("Requesting authentication at IdP.");
		// calculate authentication value
		String userPassword = procCfg.getUser() + ":" + procCfg.getPass();
		String basicAuth = Base64.getEncoder().encodeToString(userPassword.getBytes(StandardCharsets.UTF_8));

		String samlRes = c.target(URI.create(procCfg.getEcpUrl()))
				.request()
				.accept("text/xml")
				.header("Authorization", "Basic " + basicAuth)
				.post(Entity.entity(authnReq, "text/xml"), String.class);
		return samlRes;
	}

	private String performAcsReq(SamlEcpTokenConfig procCfg, Client c, String authnRes) throws WebApplicationException, ProcessingException {
		LOG.debug("Requesting auth token at ACS url.");
		String authTok = c.target(URI.create(procCfg.getAcsUrl()))
				.request()
				.accept("text/plain")
				.post(Entity.entity(authnRes, "application/vnd.paos+xml"), String.class);
		return authTok;
	}

}
