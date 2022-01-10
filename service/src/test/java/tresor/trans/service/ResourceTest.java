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



package tresor.trans.service;

import de.bund.bsi.tr_esor.api._1.ArchiveDataRequest;
import de.bund.bsi.tr_esor.api._1.DataLocation;
import de.bund.bsi.tr_esor.api._1_3.S4;
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
