/****************************************************************************
 * Copyright (C) 2021 ecsec GmbH.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file may be used in accordance with the terms and conditions
 * contained in a signed written agreement between you and ecsec GmbH.
 *
 ***************************************************************************/



package tresor.trans.service;

import io.smallrye.config.ConfigMapping;
import java.util.Optional;


/**
 *
 * @author Florian Otto
 */
@ConfigMapping(prefix = "tresor.trans.application")
public interface ApplicationConfig {

	Optional<String> cacheDir();

	Optional<Integer> mtomThreshold();

	String profileFilepath();

}
