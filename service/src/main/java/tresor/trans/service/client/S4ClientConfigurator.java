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
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;


/**
 *
 * @author Florian Otto
 */
@ApplicationScoped
public class S4ClientConfigurator {

	@Inject
	ClientConfig config;

	public void configure(S4 client) throws TresorTransClientConfigException {
		if (config.tlsConfig().isPresent()) {
			TLSProvisioning.configure(client, config.tlsConfig().get());
		} else if (config.procilonConfig().isPresent()) {
			ProcilonProvisioning.configure(client, config.procilonConfig().get());
		}
	}

}
