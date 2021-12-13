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

import de.bund.bsi.tr_esor.api._1.ArchiveDataRequest;
import de.bund.bsi.tr_esor.api._1.DataLocation;
import de.bund.bsi.tr_esor.api._1_2.S4;
import io.quarkiverse.cxf.annotation.CXFClient;
import io.quarkus.test.junit.QuarkusTest;
import javax.inject.Inject;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Testcontainers;
import tresor.trans.service.client.S4ClientConfigurator;
import tresor.trans.service.client.TresorTransClientConfigException;


/**
 *
 * @author Florian Otto
 */
@QuarkusTest
@Testcontainers
public class ResourceTest {

	@Inject
	@CXFClient
	S4 client;

	@Inject
	S4ClientConfigurator configurator;


	@Test
	public void t() throws TresorTransClientConfigException {
		configurator.configure(client);
		var archReq = new ArchiveDataRequest();
		archReq.setRequestID("a");
		archReq.setAOID("aoid");
		var dl = new DataLocation();
		var xPathQuery = new de.bund.bsi.tr_esor.api._1.ObjectFactory().createXPathFilter("//*");
		dl.setType("http://www.w3.org/TR/2007/REC-xpath20-20070123/");
		dl.getAny().add(xPathQuery);
		archReq.getDataLocation().add(dl);

		client.archiveData(archReq);
	}

}
