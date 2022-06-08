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

import de.bund.bsi.tr_esor.api._1_3.S4;
import org.apache.cxf.endpoint.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tresor.trans.service.client.ClientConfig.SamlEcpConfig;


/**
 *
 * @author Florian Otto
 */
public class SamlEcpProvisioning {
	private static final Logger LOG = LoggerFactory.getLogger(SamlEcpProvisioning.class);

	public static void configure(S4 client, SamlEcpConfig config) throws TresorTransClientConfigException {

		Client cl = (Client) client;
		cl.getOutInterceptors().add(new SoapTokenAuthHandlerCxf(config));

	}

}
