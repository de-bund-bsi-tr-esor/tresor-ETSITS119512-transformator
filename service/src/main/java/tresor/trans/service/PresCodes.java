/****************************************************************************
 * Copyright (c) 2020 Federal Office for Information Security (BSI), ecsec GmbH
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


/**
 *
 * @author Tobias Wich
 */
public class PresCodes {

	private static final String PFX = "http://uri.etsi.org/19512";

	public static final String NO_PERMISSION = PFX + "/error/noPermission";
	public static final String INT_ERROR = PFX + "/error/internalError";
	public static final String SERVICE_UNAVAIL = PFX + "/error/externalServiceUnavailable";
	public static final String PARAM_ERROR = PFX + "/error/parameterError";
	public static final String NO_SPACE_LEFT = PFX + "/error/noSpaceError";
	public static final String LOW_SPACE = PFX + "/warning/lowSpace";
	public static final String NOT_SUPPORTED = PFX + "/error/notSupported";
	public static final String UNKNOWN_PO_FORMAT = PFX + "/error/unknownPOFormat";
	public static final String PO_FORMAT_ERROR = PFX + "/error/POFormatError";
	public static final String EXISTING_POID = PFX + "/error/existingAOID";
	public static final String TRANSFER_ERROR = PFX + "/error/transferError";
	public static final String UNKNOWN_DELTA_POC_TYPE = PFX + "/error/unknownDeltaPOCType";
	public static final String INT_ERROR_DELTA_POC = PFX + "/error/DeltaPOCInternalProblem";
	public static final String UNKNOWN_POID = PFX + "/error/unknownPOID";
	public static final String UNKNOWN_VERSION = PFX + "/error/unknownVersionID";
	public static final String PARTLY_SUCCESSFUL = PFX + "/warning/requestOnlyPartlySuccessful";

}
