/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright (c) 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MediaSession.h"

#include <iostream>
#include <stdio.h>
#include <sstream>

#ifdef USE_SVP
#include "gst_svp_meta.h"
#endif

using namespace std;

extern WPEFramework::Core::CriticalSection drmAppContextMutex_;

const DRM_WCHAR PLAY[] = { ONE_WCHAR('P', '\0'),
                           ONE_WCHAR('l', '\0'),
                           ONE_WCHAR('a', '\0'),
                           ONE_WCHAR('y', '\0'),
                           ONE_WCHAR('\0', '\0')
};
const DRM_CONST_STRING PLAY_RIGHT = CREATE_DRM_STRING(PLAY);

const KeyId KeyId::EmptyKeyId;

namespace CDMi {

std::map<KeyId, DECRYPT_CONTEXT> mBindMap;
static const DRM_CONST_STRING* RIGHTS[] = { &PLAY_RIGHT };

std::string convertToBase64(const std::vector<uint8_t>& data) {
    static const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(lookup[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(lookup[((val << (8 - (valb + 8))) >> 2) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

MediaKeySession::MediaKeySession(const uint8_t drmHeader[], uint32_t drmHeaderLength, DRM_APP_CONTEXT * poAppContext, bool initiateChallengeGeneration /* = false */)
   : m_pbRevocationBuffer(nullptr)
   , m_eKeyState(KEY_CLOSED)
   , m_pbChallenge(nullptr)
   , m_cbChallenge(0)
   , m_pchSilentURL(nullptr)
   , m_piCallback(nullptr)
   , mSessionId(0)
   , mInitiateChallengeGeneration(initiateChallengeGeneration)
   , m_cHeaderKIDs(0)
   , m_pdstrHeaderKIDs( nullptr )
   , m_eHeaderVersion( DRM_HEADER_VERSION_UNKNOWN )
   , m_oBatchID( DRM_ID_EMPTY )
   , m_currentDecryptContext( nullptr )
#ifdef USE_SVP
   , m_pSVPContext(nullptr)
   , m_rpcID(0)
#endif
   , m_fCommit(false)
   , m_poAppContext(poAppContext)
   , m_decryptInited(false)
   , m_bDRMInitializedLocally(false)
{
    ZEROMEM(m_rgchSessionID, SIZEOF(m_rgchSessionID));

    PR_LOG(PR_LOG_DEBUG, "entry");

#ifdef USE_SVP
    gst_svp_ext_get_context(&m_pSVPContext, Client, m_rpcID);
    m_stSecureBuffInfo.bCreateSecureMemRegion = true;
    m_stSecureBuffInfo.SecureMemRegionSize = 512 * 1024;

    if( 0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, m_stSecureBuffInfo.SecureMemRegionSize))
    {
        m_stSecureBuffInfo.SecureMemRegionSize = 0;
    }
#endif

    mDrmHeader.clear();
    mDrmHeader.resize(drmHeaderLength);

    if(drmHeaderLength) {
        memcpy(&mDrmHeader[0], drmHeader, drmHeaderLength);
        std::string base64Header = convertToBase64(mDrmHeader); 
        PR_LOG(PR_LOG_TRACE, "DRM Header size[%u] (String):[%s]",mDrmHeader.size(), base64Header.c_str());
    } else {
        PR_LOG(PR_LOG_DEBUG, "drmHeaderLength is zero");
    }

    m_eKeyState = KEY_INIT;
    PR_LOG(PR_LOG_DEBUG, "exit");
}

uint32_t MediaKeySession::GetSessionIdExt() const
{
    PR_LOG(PR_LOG_DEBUG, "Get mSessionId[%d]", mSessionId);
    return mSessionId;
}

CDMi_RESULT MediaKeySession::SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
    PR_LOG(PR_LOG_DEBUG, "entry");
    SafeCriticalSection systemLock(drmAppContextMutex_);

    mDrmHeader.clear();
    mDrmHeader.resize(drmHeaderLength);

    if(drmHeaderLength) {
        memcpy(&mDrmHeader[0], drmHeader, drmHeaderLength);
        std::string base64Header = convertToBase64(mDrmHeader);
        PR_LOG(PR_LOG_TRACE, "DRM Header size[%u] (String):[%s]",mDrmHeader.size(), base64Header.c_str());
    } else {
        PR_LOG(PR_LOG_DEBUG, "drmHeaderLength is zero");
    }

    PR_LOG(PR_LOG_DEBUG, "exit");
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::BindKeyNow(DECRYPT_CONTEXT decryptContext)
{
    DRM_VOID * pvData = nullptr;
    DECRYPT_CONTEXT tmpDecryptContext;
    DRM_DWORD decryptionMode;
    bool bIsAudioNeedNonSVPContext;
    CDMi_RESULT result = CDMi_SUCCESS;
    DRM_RESULT dr;

    PR_LOG(PR_LOG_DEBUG, "entry");

    for(;;)
    {

        if ( CDMi_SUCCESS != SetKeyIdProperty( decryptContext->keyId ) )
        {
            result = CDMi_S_FALSE;
            break;
        }

        decryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;

        dr = Drm_Content_SetProperty(m_poAppContext,
                                DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                (const DRM_BYTE*)&decryptionMode,
                                sizeof decryptionMode);
        if (!DRM_SUCCEEDED(dr)) {
            PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
            result = CDMi_S_FALSE;
            break;
        }

        dr = ReaderBind(
                        RIGHTS,
                        sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                        _PolicyCallback,
                        pvData,
                        &(decryptContext->oDrmDecryptContext ) );

        if (DRM_FAILED(dr))
        {
            PR_LOG(PR_LOG_ERROR, "ReaderBind failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
            result = CDMi_S_FALSE;
            break;
        }

        dr = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, pvData);
        if (DRM_FAILED(dr))
        {
            PR_LOG(PR_LOG_ERROR, "Drm_Reader_Commit failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
            result = CDMi_S_FALSE;
            break;
        }

        bIsAudioNeedNonSVPContext = svpIsAudioNeedNonSVPContext();
        PR_LOG(PR_LOG_TRACE, "bIsAudioNeedNonSVPContext[%d]", bIsAudioNeedNonSVPContext);

        if(bIsAudioNeedNonSVPContext)
        {
            decryptionMode = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
            dr = Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                    (const DRM_BYTE*)&decryptionMode,
                                    sizeof decryptionMode);
            if (!DRM_SUCCEEDED(dr)) {
                PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
                result = CDMi_S_FALSE;
                break;
            }

            dr = ReaderBind(
                            RIGHTS,
                            sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                            _PolicyCallback,
                            pvData,
                            &(decryptContext->oDrmDecryptAudioContext ) );

            if (DRM_FAILED(dr))
            {
                PR_LOG(PR_LOG_ERROR, "ReaderBind failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
                result = CDMi_S_FALSE;
                break;
            }

            dr = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, pvData);
            if (DRM_FAILED(dr))
            {
                PR_LOG(PR_LOG_ERROR, "Drm_Reader_Commit failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
                result = CDMi_S_FALSE;
                break;
            }
        }

        if ( nullptr == ( tmpDecryptContext = GetDecryptCtx( decryptContext->keyId ) ) ){
            m_DecryptContextVector.push_back(decryptContext);
            PR_LOG(PR_LOG_DEBUG, "decryptContext updated successfully keyId[%s]", printGuid( decryptContext->keyId));
        }
        break;
    }

    PR_LOG(PR_LOG_DEBUG, "exit result:%u", result);
    return result;
}

CDMi_RESULT MediaKeySession::BindKey(KeyId keyId)
{
    DECRYPT_CONTEXT decryptContext;
    CDMi_RESULT result = CDMi_SUCCESS;

    PR_LOG(PR_LOG_DEBUG, "entry");

    decryptContext = NEW_DECRYPT_CONTEXT();
    decryptContext->keyId = keyId;
    
    auto it = mBindMap.find(keyId);

    for(;;)
    {
        if (it != mBindMap.end())
        {
            it->second = decryptContext;
            break;
        }

        result = BindKeyNow(decryptContext);
        if (CDMi_SUCCESS != result)
        {
            break;
        }
        mBindMap.insert(std::make_pair(decryptContext->keyId, std::shared_ptr<__DECRYPT_CONTEXT>()));

        break;
    }

    PR_LOG(PR_LOG_DEBUG, "exit result:0x%X", result);
    return result;
}

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t f_rgbLicenseData[], uint32_t f_cbLicenseDataSize, uint8_t * f_pSecureStopId)
{
    DRM_RESULT err = DRM_SUCCESS;
    DRM_LICENSE_RESPONSE oLicenseResponse = {eUnknownProtocol, 0};
    DRM_LICENSE_ACK *pLicenseAck = nullptr;

    PR_LOG(PR_LOG_DEBUG, "entry");

    SafeCriticalSection systemLock(drmAppContextMutex_);

    if ( f_cbLicenseDataSize == 0 )
    {
        PR_LOG(PR_LOG_ERROR, "f_cbLicenseDataSize is zero");
        return CDMi_INVALID_ARG;
    }

    if(f_pSecureStopId == NULL) {
        PR_LOG(PR_LOG_WARN, "f_pSecureStopId is null");
    }

    KeyId tmpBatchKeyId(&m_oBatchID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);

    if ( tmpBatchKeyId == KeyId::EmptyKeyId ){
        PR_LOG(PR_LOG_ERROR, "Invalid batchId/SecureStopId: %s",tmpBatchKeyId.B64Str());
        return CDMi_S_FALSE;
    }

    DRM_BYTE *pbLicenseData = ( DRM_BYTE * )&f_rgbLicenseData[ 0 ];

    err = ProcessLicenseResponse(
            DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
            pbLicenseData,
            f_cbLicenseDataSize,
            &oLicenseResponse );

    if (DRM_FAILED(err)) {
        SAFE_OEM_FREE( oLicenseResponse.m_pAcks );
        PR_LOG(PR_LOG_ERROR, "ProcessLicenseResponse failed. 0x%X - %s",err,DRM_ERR_NAME(err));
        return CDMi_S_FALSE;
    }

    // NOTE: Netflix, for persistent licenses, the response batchId will be empty
    //       and this check will have to be removed, but for non-persistent, any empty batchId
    //       is an issue.  The member m_oBatchId is generated in the GenerateChallenge
    //       call and that should be used for secureStopId and should match the returned
    //       batchId in the LICENSE_RESPONSE struct  for in-memory licenses.
    if ( ::memcmp( m_oBatchID.rgb, &oLicenseResponse.m_idSession.rgb[0], DRM_ID_SIZE ) != 0 )
    {
        KeyId mBatch(&m_oBatchID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);
        PR_LOG(PR_LOG_ERROR, "Response batchID does not equal batchID %s from challenge.",mBatch.B64Str());
        SAFE_OEM_FREE( oLicenseResponse.m_pAcks );
        return CDMi_S_FALSE;
    }

    for ( DRM_DWORD i = 0; i < oLicenseResponse.m_cAcks; ++i) {
        pLicenseAck = oLicenseResponse.m_pAcks != nullptr
                ? &oLicenseResponse.m_pAcks[ i ] : &oLicenseResponse.m_rgoAcks[ i ];

        KeyId keyId(pLicenseAck->m_oKID.rgb,KeyId::KEYID_ORDER_GUID_LE);

        DRM_RESULT dr = pLicenseAck->m_dwResult;

        if (DRM_SUCCEEDED( dr )) {
            if ( m_piCallback != nullptr ){
                if (CDMi_SUCCESS != BindKey(keyId))
                {
                    PR_LOG(PR_LOG_DEBUG, "BindKey() failed for keyId %s",printGuid(keyId));
                }
                if ( keyId.getKeyIdOrder() == KeyId::KEYID_ORDER_GUID_LE ) {
                    keyId.ToggleFormat();
                }

                m_piCallback->OnKeyStatusUpdate("KeyUsable", (const uint8_t *)keyId.getmBytes(), DRM_ID_SIZE);
                PR_LOG(PR_LOG_DEBUG, "Notified the Key status update as KeyUsable");
            }
        }
        else
        {
            PR_LOG(PR_LOG_ERROR, "Error processing license %s, 0x%X - %s",printGuid(keyId),dr,DRM_ERR_NAME(dr));
        }
    }

    if ( m_piCallback != nullptr ) {
        m_piCallback->OnKeyStatusesUpdated();
    }

    if(f_pSecureStopId != NULL) {
        memset( f_pSecureStopId, 0, DRM_ID_SIZE );
        ::memcpy( f_pSecureStopId, &m_oBatchID.rgb[ 0 ], DRM_ID_SIZE );
    }

    SAFE_OEM_FREE( oLicenseResponse.m_pAcks );

    PR_LOG(PR_LOG_DEBUG, "success");
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::SelectKeyId( const uint8_t f_keyLength, const uint8_t f_keyId[] )
{
    SafeCriticalSection systemLock(drmAppContextMutex_);
    DRM_RESULT err;
    DRMPFNPOLICYCALLBACK pfnOPLCallback = nullptr;
    DRM_VOID * pvData = nullptr;
    DRM_DWORD decryptionMode;
    CDMi_RESULT result = CDMi_SUCCESS;
    bool bIsAudioNeedNonSVPContext;

    PR_LOG(PR_LOG_DEBUG, "entry");

    pfnOPLCallback = _PolicyCallback;

    for (;;)
    {
        if ( f_keyId == nullptr || f_keyLength != DRM_ID_SIZE )
        {
            PR_LOG(PR_LOG_ERROR, "Bad value for keyId arg");
            result = CDMi_INVALID_ARG;
            break;
        }

        KeyId keyId(&f_keyId[0],KeyId::KEYID_ORDER_UUID_BE);
        std::string keyIdHex(keyId.HexStr());

        /* If decrypt context exists, no need to create the new one */
        if ( nullptr != ( m_currentDecryptContext = GetDecryptCtx( keyId ) ) ){
            PR_LOG(PR_LOG_DEBUG, "Decrypt contex found for the keyid");
            result = CDMi_SUCCESS;
            break;
        }

        if ( CDMi_SUCCESS != SetKeyIdProperty( keyId ) )
        {
            PR_LOG(PR_LOG_ERROR, "SetKeyIdProperty failed");
            result = CDMi_S_FALSE;
            break;
        }

        DECRYPT_CONTEXT decryptContext = NEW_DECRYPT_CONTEXT();

        decryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
        err = Drm_Content_SetProperty(m_poAppContext,
                                DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                (const DRM_BYTE*)&decryptionMode,
                                sizeof decryptionMode);
        if (!DRM_SUCCEEDED(err)) {
            PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            result = CDMi_S_FALSE;
            break;
        }

        err = ReaderBind(
                        RIGHTS,
                        sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                        pfnOPLCallback,
                        pvData,
                        &(decryptContext->oDrmDecryptContext ) );

        if (DRM_FAILED(err))
        {
            PR_LOG(PR_LOG_ERROR, "ReaderBind failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            result = CDMi_S_FALSE;
            break;
        } 

        err = Drm_Reader_Commit(m_poAppContext, pfnOPLCallback, pvData);
        if (DRM_FAILED(err))
        {
            PR_LOG(PR_LOG_ERROR, "Drm_Reader_Commit failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            result = CDMi_S_FALSE;
            break;
        }

        bIsAudioNeedNonSVPContext = svpIsAudioNeedNonSVPContext();

        if(bIsAudioNeedNonSVPContext)
        {
            decryptionMode = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
            err = Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                    (const DRM_BYTE*)&decryptionMode,
                                    sizeof decryptionMode);
            if (!DRM_SUCCEEDED(err)) {
                PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty failed. 0x%X - %s",err,DRM_ERR_NAME(err));
                result = CDMi_S_FALSE;
                break;
            }

            err = ReaderBind(
                            RIGHTS,
                            sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                            pfnOPLCallback,
                            pvData,
                            &(decryptContext->oDrmDecryptAudioContext ) );

            if (DRM_FAILED(err))
            {
                PR_LOG(PR_LOG_ERROR, "ReaderBind failed. 0x%X - %s",err,DRM_ERR_NAME(err));
                result = CDMi_S_FALSE;
                break;
            }

            err = Drm_Reader_Commit(m_poAppContext, pfnOPLCallback, pvData);
            if (DRM_FAILED(err))
            {
                PR_LOG(PR_LOG_ERROR, "Drm_Reader_Commit failed. 0x%X - %s",err,DRM_ERR_NAME(err));
                result = CDMi_S_FALSE;
                break;
            }
        }

        m_fCommit = TRUE;
        m_decryptInited = true;
        decryptContext->keyId = keyId;
        m_DecryptContextVector.push_back(decryptContext);
        m_currentDecryptContext = decryptContext;
        
        break;
    }

    PR_LOG(PR_LOG_DEBUG, "exit result:0x%X", result);
    return result;
}

CDMi_RESULT MediaKeySession::GetChallengeDataExt(uint8_t * f_pChallenge, uint32_t & f_ChallengeSize, uint32_t f_isLDL)
{
    DRM_RESULT err;
    DRM_CHAR *pchCustomData = nullptr;
    DRM_DWORD cchCustomData = 0;

    PR_LOG(PR_LOG_DEBUG, "entry");
    UNREFERENCED_PARAMETER( f_isLDL );

    SafeCriticalSection systemLock(drmAppContextMutex_);

    if (mDrmHeader.size() == 0)
    {
        PR_LOG(PR_LOG_ERROR, "No valid DRM header");
        return CDMi_S_FALSE;
    }

    std::string base64Header = convertToBase64(mDrmHeader);
    PR_LOG(PR_LOG_TRACE, "DRM Header size[%u] (String):[%s]",mDrmHeader.size(), base64Header.c_str());

    ASSERT(m_poAppContext != nullptr);

    err = Drm_Content_SetProperty(m_poAppContext,
                                  DRM_CSP_AUTODETECT_HEADER,
                                  &mDrmHeader[0],
                                  mDrmHeader.size());
    if (DRM_FAILED(err))
    {
        PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty failed. 0x%X - %s",err,DRM_ERR_NAME(err));
        return CDMi_S_FALSE;
    }

    if(f_pChallenge == NULL) {
        PR_LOG(PR_LOG_WARN, "Input challenge buffer is null, need to return the required challengesize");
    }

    DRM_BYTE* pbPassedChallenge = static_cast<DRM_BYTE*>(f_pChallenge);
    if (f_ChallengeSize == 0) {
        PR_LOG(PR_LOG_WARN, "Input ChallengeSize is zero");
        pbPassedChallenge = nullptr;
    }


    err = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                           RIGHTS,
                                           sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
                                           nullptr,  // domain id
                                           pchCustomData,  // custom data
                                           cchCustomData,        // custom data size
                                           nullptr,  // silent URL
                                           0,        // silent URL size
                                           nullptr,  // non-silent URL
                                           0,        // non-silent URL size
                                           pbPassedChallenge,
                                           &f_ChallengeSize,
                                           &m_oBatchID );


    if ( DRM_FAILED( err ) )
    {
        if (err == DRM_E_BUFFERTOOSMALL) {
            PR_LOG(PR_LOG_WARN, "challenge buffer is small, required size is %u", f_ChallengeSize);
            return CDMi_OUT_OF_MEMORY;
        }
        else
        {
            PR_LOG(PR_LOG_ERROR, "Drm_LicenseAcq_GenerateChallenge failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            return CDMi_S_FALSE;
        }
    }

    m_eKeyState = KEY_PENDING;

    PR_LOG(PR_LOG_DEBUG, "exit");

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CancelChallengeDataExt()
{
    PR_LOG(PR_LOG_DEBUG, "Not implemented ");
    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Unbind(KeyId keyId)
{
    auto it = mBindMap.find(keyId);
 
    PR_LOG(PR_LOG_DEBUG, "entry");
    PR_LOG(PR_LOG_TRACE, "keyid[%s]", printGuid(keyId));
    
    if (it == mBindMap.end())
    {
        PR_LOG(PR_LOG_ERROR, "failed to find binding lock with key ID");
        return CDMi_S_FALSE;
    }

    if (it->second.get() == nullptr)
    {
        mBindMap.erase(it);
        return CDMi_SUCCESS;
    }

    if (it->second->keyId != keyId)
    {
        ASSERT(it->second->keyId == keyId);

        PR_LOG(PR_LOG_ERROR, "keyId does not match map key");
        return CDMi_S_FALSE;
    }

    BindKeyNow(it->second);
    it->second.reset();
    mBindMap.erase(it);

    PR_LOG(PR_LOG_DEBUG, "exit");
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CleanDecryptContext()
{
    SafeCriticalSection systemLock(drmAppContextMutex_);

    PR_LOG(PR_LOG_DEBUG, "entry");

    ASSERT(m_poAppContext != nullptr);

    for (DECRYPT_CONTEXT &ctx : m_DecryptContextVector)
    {
        PR_LOG(PR_LOG_DEBUG, "unbind keyIds from Decrypt context");
        Unbind(ctx->keyId);
    }

    CloseDecryptContexts();

    if (m_poAppContext && !m_fCommit)
    {
        DRM_RESULT err = Drm_Reader_Commit(m_poAppContext, nullptr, nullptr);
        if (DRM_FAILED(err))
        {
            PR_LOG(PR_LOG_DEBUG, "Drm_Reader_Commit failed. 0x%X - %s",err,DRM_ERR_NAME(err));
        }
    }

    m_fCommit = FALSE;
    m_decryptInited = false;
    PR_LOG(PR_LOG_DEBUG, "exit");
    return CDMi_SUCCESS;
}
}

