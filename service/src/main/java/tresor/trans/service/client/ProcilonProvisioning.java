/****************************************************************************
 * Copyright (C) 2021 ecsec GmbH.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file may be used in accordance with the terms and conditions
 * contained in a signed written agreement between you and ecsec GmbH.
 *
 ***************************************************************************/



package tresor.trans.service.client;

import de.bund.bsi.tr_esor.api._1_2.S4;
import org.apache.cxf.endpoint.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tresor.trans.service.client.ClientConfig.ProcilonConfig;


/**
 *
 * @author Florian Otto
 */
public class ProcilonProvisioning {
	private static final Logger LOG = LoggerFactory.getLogger(ProcilonProvisioning.class);

	public static void configure(S4 client, ProcilonConfig config) throws TresorTransClientConfigException {

		Client cl = (Client) client;
		cl.getOutInterceptors().add(new SoapTokenAuthHandlerCxf(config));

	}

}
