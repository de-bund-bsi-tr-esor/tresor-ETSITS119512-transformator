/****************************************************************************
 * Copyright (C) 2022 ecsec GmbH.
 * All rights reserved.
 * Contact: ecsec GmbH (info@ecsec.de)
 *
 * This file may be used in accordance with the terms and conditions
 * contained in a signed written agreement between you and ecsec GmbH.
 *
 ***************************************************************************/

package tresor.trans.service;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import jakarta.activation.DataSource;
import org.apache.cxf.io.CachedOutputStream;
import org.eclipse.microprofile.config.ConfigProvider;


/**
 *
 * @author Tobias Wich
 */
public class TempFileDataSource implements DataSource {

	private final CachedOutputStream cache;
	private String name;
	private String contentType;

	public TempFileDataSource(String contentType) throws IOException {
		this(null, contentType);
	}

	public TempFileDataSource(String name, String contentType) throws IOException {
		this.name = name;
		this.contentType = contentType;
		this.cache = new CachedOutputStream();

		var tmpDir = ConfigProvider.getConfig().getOptionalValue("tresor.trans.application.cache-dir", String.class).orElse((System.getProperty("java.io.tmpdir")));
		this.cache.setOutputDir(new File(tmpDir));
	}

	@Override
	public InputStream getInputStream() throws IOException {
		return cache.getInputStream();
	}

	@Override
	public OutputStream getOutputStream() {
		return cache;
	}

	public void lock() throws IOException {
		cache.lockOutputStream();
	}

	@Override
	public String getContentType() {
		return contentType;
	}

	@Override
	public String getName() {
		return name;
	}

}
