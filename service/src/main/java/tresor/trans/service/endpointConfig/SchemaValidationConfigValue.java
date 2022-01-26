/****************************************************************************
 * Copyright (C) 2021 ecsec GmbH.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file may be used in accordance with the terms and conditions
 * contained in a signed written agreement between you and ecsec GmbH.
 *
 ***************************************************************************/


package tresor.trans.service.endpointConfig;

import org.eclipse.microprofile.config.ConfigProvider;

/**
 *
 * @author Florian Otto
 */
public class SchemaValidationConfigValue {

	private final String configValue;

	public SchemaValidationConfigValue() {
		this.configValue = ConfigProvider.getConfig().getOptionalValue("tresor.trans.endpoint.schema-validation-enabled", String.class).orElse("NONE");
	}

	public String toString() {
		return this.configValue;
	}

}
