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

import java.io.File;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 *
 * @author Florian Otto
 */
public class AttachementDirectoryConfigValue extends File {

	public AttachementDirectoryConfigValue() {
		super(
			ConfigProvider.getConfig().getOptionalValue("tresor.trans.endpoint.mtom-directory", String.class).orElse(("/tmp"))
		);
	}

}
