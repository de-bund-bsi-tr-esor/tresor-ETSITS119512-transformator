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


/**
 *
 * @author Tobias Wich
 */
public class TresorCodes {

	private static final String PFX = "http://www.bsi.bund.de/tr-esor/api/1.3/";

	private static final String MAJOR = PFX + "resultmajor";
	private static final String MINOR = PFX + "resultminor";

	public static final String OK = MAJOR + "#ok";
	public static final String ERROR = MAJOR + "#error";
	public static final String WARN = MAJOR + "#warning";

	public static final String NO_PERMISSION = MINOR + "/al/common#noPermission";
	public static final String INT_ERROR = MINOR + "/al/common#internalError";
	public static final String PARAM_ERROR = MINOR + "/al/common#parameterError";
	public static final String NO_SPACE_LEFT = MINOR + "/arl/noSpaceError";
	public static final String LOW_SPACE = MINOR + "/arl/lowSpaceWarning";
	public static final String NOT_SUPPORTED = MINOR + "/arl/notSupported";
	public static final String UNKNOWN_ARCHIVE_DATA_TYPE = MINOR + "/arl/unknownArchiveDataType";
	public static final String UNKNOWN_PO_FORMAT = MINOR + "/arl/unknownPOFormat";
	public static final String UNKNOWN_AOID = MINOR + "/arl/unknownAOID";
	public static final String UNKNOWN_VERSION = MINOR + "/arl/unknownVersionID";
	public static final String XAIP_NOK = MINOR + "/arl/XAIP_NOK";
	public static final String XAIP_NOK_EXPIRED = MINOR + "/arl/XAIP_NOK_EXPIRED";
	public static final String XAIP_NOK_SUBMTIME = MINOR + "/arl/XAIP_NOK_SUBMTIME";
	public static final String XAIP_NOK_SIG = MINOR + "/arl/XAIP_NOK_SIG";
	public static final String XAIP_NOK_ER = MINOR + "/arl/XAIP_NOK_ER";
	public static final String DXAIP_NOK = MINOR + "/arl/DXAIP_NOK";
	public static final String DXAIP_NOK_EXPIRED = MINOR + "/arl/DXAIP_NOK_EXPIRED";
	public static final String DXAIP_NOK_SUBMTIME = MINOR + "/arl/DXAIP_NOK_SUBMTIME";
	public static final String DXAIP_NOK_SIG = MINOR + "/arl/DXAIP_NOK_SIG";
	public static final String DXAIP_NOK_ID = MINOR + "/arl/DXAIP_NOK_ID";
	public static final String DXAIP_NOK_AOID = MINOR + "/arl/DXAIP_NOK_AOID";
	public static final String DXAIP_NOK_VERSION = MINOR + "/arl/DXAIP_NOK_Version";
	public static final String EXISTING_AOID = MINOR + "/arl/existingAOID";
	public static final String EXISTING_PACKAGE_WARN = MINOR + "/arl/existingPackageInfoWarning";
	public static final String PARTLY_SUCCESSFUL = MINOR + "/arl/requestOnlyPartlySuccessfulWarning";
	public static final String MISSING_REASON_OF_DELETION = MINOR + "/arl/missingReasonOfDeletion";
	public static final String UNKNOWN_LOCATION = MINOR + "/arl/unknownLocation";

}
