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

import java.util.Optional;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 *
 * @author Florian Otto
 */
public class AttachementMemoryThresholdConfigValue extends Number {

	private final Optional<Integer> configValue;

	public AttachementMemoryThresholdConfigValue() {
		this.configValue = ConfigProvider.getConfig().getOptionalValue("tresor.trans.application.mtom-threshold", Integer.class);
	}

	@Override
	public int intValue() {
		return this.configValue.orElse(0);
	}

	@Override
	public long longValue() {
		return this.intValue();
	}

	@Override
	public float floatValue() {
		return this.intValue();
	}

	@Override
	public double doubleValue() {
		return this.intValue();
	}

}
