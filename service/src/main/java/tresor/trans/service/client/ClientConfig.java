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

import io.smallrye.config.ConfigMapping;
import java.time.Duration;
import java.util.Optional;


/**
 *
 * @author Florian Otto
 */
@ConfigMapping(prefix = "tresor.trans.client")
public interface ClientConfig {

	public Optional<TLSConfig> tlsConfig();

	public Optional<ProcilonConfig> procilonConfig();

	public static interface ProcilonConfig {
		String authnUrl();

		String ecpUrl();

		String acsUrl();

		String user();

		String pass();

		Duration tokenValidity();
	}

	public static interface TLSConfig {

		public String keystoreFilepath();

		public String keystoreSecret();

		public String truststoreFilepath();

	}

}
