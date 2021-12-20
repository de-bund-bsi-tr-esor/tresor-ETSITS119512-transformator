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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author Tobias Wich
 */
public class SamlEcpTokenProvider {

	private final Logger LOG = LoggerFactory.getLogger(SamlEcpTokenProvider.class);

	private ClientConfig.SamlEcpConfig config;

	private Instant fetchedAt;
	private String token;

	public SamlEcpTokenProvider(ClientConfig.SamlEcpConfig config) {
		this.config = config;
	}

	public String getToken() {
		synchronized (this) {
			// if we have no token or the validity is expired
			if (fetchedAt == null || fetchedAt.plus(config.tokenValidity()).isBefore(Instant.now())) {
				token = getNewToken();
				fetchedAt = Instant.now();
			}
		}

		return token;
	}

	private String getNewToken() {
		LOG.info("Retrieving new token from SAML IdP.");
		var c = ResteasyClientBuilder.newBuilder()
			.build();

		try {
			var authnReq = performAuthnReq(c);
			var authnRes = performEcpAuth(c, authnReq);
			var newToken = performAcsReq(c, authnRes);

			return newToken;
		} catch (WebApplicationException | ProcessingException ex) {
			LOG.error("Failed to retrieve token from SAML IdP.", ex);
			// TODO: explicit error handling
			throw ex;
		}
	}

	private String performAuthnReq(Client c) throws WebApplicationException, ProcessingException {
		LOG.debug("Requesting SAML AuthnRequest.");
		return c.target(config.authnUrl())
			.request()
			.accept("application/vnd.paos+xml")
			.get(String.class);
	}

	private String performEcpAuth(Client c, String authnReq) throws WebApplicationException, ProcessingException {
		LOG.debug("Requesting authentication at IdP.");
		// calculate authentication value
		String userPassword = config.user() + ":" + config.pass();
		String basicAuth = Base64.getEncoder().encodeToString(userPassword.getBytes(StandardCharsets.UTF_8));

		return c.target(config.ecpUrl())
			.request()
			.accept("text/xml")
			.header("Authorization", "Basic " + basicAuth)
			.post(
				Entity.entity(authnReq, "text/xml"),
				String.class
			);
	}

	private String performAcsReq(Client c, String authnRes) throws WebApplicationException, ProcessingException {
		LOG.debug("Requesting auth token at ACS url.");
		return c.target(config.acsUrl())
			.request()
			.accept("text/plain")
			.post(
				Entity.entity(authnRes, "application/vnd.paos+xml"),
				String.class
			);
	}

}
