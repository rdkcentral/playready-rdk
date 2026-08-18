/*
 * Copyright (c) 2025 RDK Management
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
 */

#include "MediaSession.h"
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include <vector>
#include <sys/utsname.h>
#include <drmresults.h>

#ifdef USE_SVP
#include "gst_svp_meta.h"
#endif

extern WPEFramework::Core::CriticalSection drmAppContextMutex_;
extern DRM_CONST_STRING g_dstrCDMDrmStoreName;

#define NYI_KEYSYSTEM "keysystem-placeholder"

#ifdef DRM_WCHAR_CAST
#define WCHAR_CAST DRM_WCHAR_CAST
#endif

#ifdef DRM_CREATE_DRM_STRING
#define CREATE_DRM_STRING DRM_CREATE_DRM_STRING
#endif

#ifdef DRM_EMPTY_DRM_STRING
#define EMPTY_DRM_STRING DRM_EMPTY_DRM_STRING
#endif

#ifdef DRM_NO_OF
#define NO_OF DRM_NO_OF
#endif

#define DEVCERT_WAIT_SECS 30
#define DEVCERT_RETRY_MAX 4

#define EXPECTED_AES_CTR_IVDATA_SIZE (8)
#define EXPECTED_AES_CBC_IVDATA_SIZE (16)
using namespace std;

enum class PlayreadyInitDataType
{
    PR_INIT_DATA_DRM_HEADER = 0,
    PR_INIT_DATA_PRO,
    PR_INIT_DATA_INVALID
};

KeyId::KeyId( const DRM_BYTE *f_pBytes , KeyIdOrder keyOrder)
{
    m_hexStr.clear();
    m_base64Str.clear();
    ZEROMEM( m_bytes, DRM_ID_SIZE );
    keyIdOrder = KEYID_ORDER_UNKNOWN;
    memcpy( m_bytes, f_pBytes, DRM_ID_SIZE );
    keyIdOrder = keyOrder;
}

DRM_RESULT KeyId::keyDecode( const DRM_CONST_STRING &f_pdstrB64 ){

    DRM_DWORD cBytes = DRM_ID_SIZE;
	DRM_RESULT dr = DRM_B64_DecodeW( &f_pdstrB64, &cBytes, getmBytes(), 0 );
	if ( dr != DRM_SUCCESS )
	{
		fprintf(stderr, "\n[keyDecode] DRM_B64_DecodeW Failed");
	}
	return dr;
}

void KeyId::setKeyIdOrder(KeyIdOrder keyOrder)
{
    keyIdOrder = keyOrder;
}

KeyId::KeyIdOrder KeyId::getKeyIdOrder()
{
    return keyIdOrder;
}

DRM_BYTE* KeyId::getmBytes()
{
    return m_bytes;
}

KeyId& KeyId::ToggleFormat()
{
    DRM_BYTE tmp;

    if ( keyIdOrder != KEYID_ORDER_UNKNOWN )
    {
        tmp = m_bytes[3];
        m_bytes[3] = m_bytes[0];
        m_bytes[0] = tmp;
        tmp = m_bytes[2];
        m_bytes[2] = m_bytes[1];
        m_bytes[1] = tmp;
        tmp = m_bytes[5];
        m_bytes[5] = m_bytes[4];
        m_bytes[4] = tmp;
        tmp = m_bytes[7];
        m_bytes[7] = m_bytes[6];
        m_bytes[6] = tmp;

        if ( keyIdOrder == KEYID_ORDER_GUID_LE )
            keyIdOrder = KEYID_ORDER_UUID_BE;
        else
            keyIdOrder = KEYID_ORDER_GUID_LE;
    }
    m_hexStr.clear();
    m_base64Str.clear();

    return *this;
}

bool KeyId::operator< ( const KeyId &keyId ) const
{
    if ( memcmp(keyId.m_bytes, m_bytes, DRM_ID_SIZE) < 0 )
        return true;
    return false;
}

bool KeyId::operator== ( const KeyId &keyId )
{
    bool areEqual = false;

    if ( memcmp(&m_bytes[8], &(keyId.m_bytes[8]), 8) == 0 )
    {
        if ( memcmp(keyId.m_bytes, m_bytes, 8) == 0 )
        {
            areEqual = true;
        }
        else
        {
            ToggleFormat();
            areEqual = ( memcmp(keyId.m_bytes, m_bytes, DRM_ID_SIZE ) == 0 );
            ToggleFormat();
        }
    }

    return areEqual;
}

const char* KeyId::HexStr()
{
    if ( m_hexStr.empty() )
    {
        char hex[64];
        ::memset(hex, 0, 64);
        for (int i = 0; i < DRM_ID_SIZE; i++)
        {
            hex[i * 2] = "0123456789abcdef"[m_bytes[i] >> 4];
            hex[i * 2 + 1] = "0123456789abcdef"[m_bytes[i] & 0x0F];
        }
        m_hexStr = hex;
    }

    return m_hexStr.c_str();
}

const char* KeyId::B64Str()
{
    DRM_RESULT dr = DRM_SUCCESS;
    if ( m_base64Str.empty() )
    {
        char b64[64];
        DRM_DWORD cbB64 = 64;
        ::memset( b64, 0, 64 );
        PR4ChkDR( DRM_B64_EncodeA( m_bytes, DRM_ID_SIZE, b64, &cbB64, 0 ) );

        m_base64Str = b64;
    }

    ErrorExit:

    return m_base64Str.c_str();
}

namespace CDMi {

namespace {

void Swap(uint8_t& lhs, uint8_t& rhs)
{
    uint8_t tmp =lhs;
    lhs = rhs;
    rhs = tmp;
}

}

const DRM_CONST_STRING *g_rgpdstrRights[1] = {&g_dstrDRM_RIGHT_PLAYBACK};

uint64_t MediaKeySession::mMaxResDecodePixels = 0;
bool MediaKeySession::mMaxResDecodeSet = false;
static const DRM_CHAR  acWRMHeaderStart[]     = "<WRMHEADER";

WPEFramework::Core::CriticalSection prPlatformMutex_;
WPEFramework::Core::CriticalSection prSessionMutex_;
DRM_DWORD CPRDrmPlatform::m_dwInitRefCount = 0;

extern std::string convertToBase64(const std::vector<uint8_t>& data);

static bool IsPlayReadyHeader(const std::string& data)
{
    bool result = false;

    PR_LOG(PR_LOG_DEBUG, "entry");

    // UTF-16 LE XML
    const char utf16Tag[] =
    {
        '<',0,
        'W',0,
        'R',0,
        'M',0,
        'H',0,
        'E',0,
        'A',0,
        'D',0,
        'E',0,
        'R',0
    };

    for(;;) {
        // UTF-8 XML
        if (data.size() >= strlen(acWRMHeaderStart)
            && memcmp(data.data(), acWRMHeaderStart, strlen(acWRMHeaderStart)) == 0)
        {
            result = true;
            break;
        }

        if (data.size() >= sizeof(utf16Tag))
        {
            if (memcmp(data.data(), utf16Tag, sizeof(utf16Tag)) == 0) {
                result = true;
                break;
            }
        }

        break;
    }

    PR_LOG(PR_LOG_DEBUG, "exit: isPlayreadyHeader found [%d]", result);
    return result;
}

/*Parsing the first playready init header from _initData_. In success case the header will be stored in _output_*/
PlayreadyInitDataType parsePlayreadyInitializationData(const std::string& initData, std::string* output)
{
    BufferReader input(reinterpret_cast<const uint8_t*>(initData.data()), initData.length());

    static const uint8_t playreadySystemId[] = {
      0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86,
      0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95,
      
    };
    bool bIsPlayReadyHeader = false;
    PlayreadyInitDataType prInitDataType = PlayreadyInitDataType::PR_INIT_DATA_INVALID;

    PR_LOG(PR_LOG_DEBUG, "entry");

    for (;;) {

        if(initData.empty()) {
            PR_LOG(PR_LOG_ERROR, "initData data is empty");
            break;
        }

        bIsPlayReadyHeader = IsPlayReadyHeader(initData);

        //
        // Try initData as DRM Header of string format
        //
        if(bIsPlayReadyHeader){

            output->clear();

            if (!input.ReadString(output, initData.length())) {
                PR_LOG(PR_LOG_ERROR, "input BufferReader ReadString failed");
                break;
            }

            prInitDataType = PlayreadyInitDataType::PR_INIT_DATA_DRM_HEADER;
            PR_LOG(PR_LOG_DEBUG, "INIT_DATA_DRM_HEADER found initData.length[%d]", initData.length());
            break;
        }

        while (!input.IsEOF()) {
            size_t startPosition = input.pos();

            uint64_t atomSize;

            if (!input.Read4Into8(&atomSize)) {
                break;
            }

            std::vector<uint8_t> atomType;
            if (!input.ReadVec(&atomType, 4)) {
                break;
            }

            if (atomSize == 1) {
                if (!input.Read8(&atomSize)) {
                    break;
                }
            } else if (atomSize == 0) {
                atomSize = input.size() - startPosition;
            }

            if (memcmp(&atomType[0], "pssh", 4)) {
                if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                    break;
                }
                continue;
            }

            PR_LOG(PR_LOG_DEBUG, "PSSH data identified in InitData");

            uint8_t version;
            if (!input.Read1(&version)) {
                break;
            }

            if (version > 1) {
                if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                    break;
                }
                continue;
            }

            if (!input.SkipBytes(3)) {
                break;
            }

            std::vector<uint8_t> systemId;
            if (!input.ReadVec(&systemId, sizeof(playreadySystemId))) {
                break;
            }

            if (memcmp(&systemId[0], playreadySystemId, sizeof(playreadySystemId))) {
                if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                    break;
                }
                continue;
            }

            PR_LOG(PR_LOG_DEBUG, "Playready SystemId matched!");

            if (version == 1) {
                uint32_t numKeyIds;
                if (!input.Read4(&numKeyIds)) {
                    break;
                }

                if (!input.SkipBytes(numKeyIds * 16)) {
                    break;
                }
            }

            uint32_t dataLength;
            if (!input.Read4(&dataLength)) {
                break;
            }

            output->clear();
            if (!input.ReadString(output, dataLength)) {
                break;
            }

            PR_LOG(PR_LOG_TRACE, "InitData parse success! dataLength[%d]", dataLength);
            prInitDataType = PlayreadyInitDataType::PR_INIT_DATA_PRO;
            break;
        }

        break;
    }

  PR_LOG(PR_LOG_DEBUG, "exit: prInitDataType[%u]", prInitDataType );

  return prInitDataType;
}

/*
 * f_pContext(input) : It could be NULL or Valid pointer
 */
DRM_RESULT CPRDrmPlatform::DrmPlatformInitialize( void *f_pContext )
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_DWORD cAttempts = 0;

    PR_LOG(PR_LOG_DEBUG, "entry m_dwInitRefCount[%d]", m_dwInitRefCount);

    SafeCriticalSection systemLock(prPlatformMutex_);

    if (m_dwInitRefCount) {
        PR_LOG(PR_LOG_WARN, "Already initialized. InitRefCount[%u]",m_dwInitRefCount);
        goto ErrorExit;
    }

    while( ( dr=Drm_Platform_Initialize( f_pContext ) ) == DRM_E_DEPRECATED_DEVCERT_READ_ERROR) {

        Drm_Platform_Uninitialize( (void *)nullptr );

        if ( cAttempts >= DEVCERT_RETRY_MAX ){
            ChkDR( DRM_E_DEPRECATED_DEVCERT_READ_ERROR);
        }
        sleep( DEVCERT_WAIT_SECS );
        ++cAttempts;
    }

ErrorExit:
    if ( DRM_FAILED( dr ) ) {
        m_dwInitRefCount = 0;
        PR_LOG(PR_LOG_ERROR, "failed. InitRefCount[%u] 0x%X - %s",m_dwInitRefCount,dr,DRM_ERR_NAME(dr));
    } else {
        m_dwInitRefCount = 1;
        PR_LOG(PR_LOG_ERROR, "success. InitRefCount[%u]",m_dwInitRefCount);
    }

    return dr;
}

DRM_RESULT CPRDrmPlatform::DrmPlatformInitialize()
{
    DRM_RESULT dr = DRM_SUCCESS;
    void *pPlatformInitData = NULL;

    PR_LOG(PR_LOG_DEBUG, "entry");

    svpGetDrmPlatformInitData( &pPlatformInitData);
    
    dr = DrmPlatformInitialize( (void *)pPlatformInitData );

    PR_LOG(PR_LOG_DEBUG, "exit: 0x%X - %s", dr,DRM_ERR_NAME(dr));
    return dr;
}

DRM_RESULT CPRDrmPlatform::DrmPlatformUninitialize()
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_VOID *pDrmOemContext = NULL;

    PR_LOG(PR_LOG_DEBUG, "entry InitRefCount[%u]", m_dwInitRefCount);

    SafeCriticalSection systemLock(prPlatformMutex_);

    if (!m_dwInitRefCount) {
        PR_LOG(PR_LOG_WARN, "Platform is not initialized for DRM. InitRefCount[%u]",m_dwInitRefCount);
        goto ErrorExit;
    }

    svpGetDrmOEMContext(&pDrmOemContext);

    if ( DRM_FAILED( (dr=Drm_Platform_Uninitialize( (void *)pDrmOemContext ) ) ) )
    {
        PR_LOG(PR_LOG_ERROR, "Drm_Platform_Uninitialize failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
        goto ErrorExit;
    }
    m_dwInitRefCount = 0;

ErrorExit:
    if ( DRM_FAILED( dr ) ) {
        PR_LOG(PR_LOG_ERROR, " failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
    } else {
        PR_LOG(PR_LOG_DEBUG, "exit success");
    }

    return dr;

}

/*Get the version and list of keyids from the header*/
DRM_RESULT Header_GetInfo(
        const DRM_CONST_STRING      *f_pdstrWRMHEADER,
              eDRM_HEADER_VERSION   *f_pHeaderVersion,
              DRM_CONST_STRING     **f_ppdstrKIDs,
              DRM_DWORD             *f_pcbKIDs)
{
    DRM_RESULT          dr              = DRM_SUCCESS;
    DRM_DWORD           cKIDs           = 0;
    DRM_CONST_STRING   *pdstrKIDs       = NULL;

    PR_LOG(PR_LOG_DEBUG, "entry");

    PR4ChkDR( DRM_HDR_GetHeaderVersion( f_pdstrWRMHEADER, f_pHeaderVersion ) );

    PR4ChkDR( DRM_HDR_GetAttribute(
         f_pdstrWRMHEADER,
         NULL,
         DRM_HEADER_ATTRIB_KIDS,
         NULL,
         &cKIDs,
         &pdstrKIDs,
         0 ) );

    *f_ppdstrKIDs = pdstrKIDs;
    *f_pcbKIDs = cKIDs;

ErrorExit:
    if ( DRM_FAILED( dr ) ) {
        PR_LOG(PR_LOG_ERROR, " failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
    } else {
        PR_LOG(PR_LOG_DEBUG, "exit success");
    }
    return dr;
}

PlayreadySession::PlayreadySession() 
    : m_poAppContext(nullptr)
    , m_pbPROpaqueBuf(nullptr)
    , m_cbPROpaqueBuf(0)
    , m_bInitCalled(false)
{
    void *pPlatformInitData = NULL;
    DRM_RESULT dr = DRM_SUCCESS;

    PR_LOG(PR_LOG_DEBUG, "entry");

    svpGetDrmPlatformInitData( &pPlatformInitData);

    dr = CPRDrmPlatform::DrmPlatformInitialize(pPlatformInitData);

    if (DRM_FAILED( dr )) {
        PR_LOG(PR_LOG_ERROR, "failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
    } else {
        PR_LOG(PR_LOG_DEBUG, "exit success");
    }
}

PlayreadySession::~PlayreadySession()
{
    DRM_RESULT dr = DRM_SUCCESS;

    PR_LOG(PR_LOG_DEBUG, "entry");

    SafeCriticalSection systemLock(prSessionMutex_);

    if ( IsPlayreadySessionInit() )
    {
        SAFE_OEM_FREE(m_pbPROpaqueBuf);
        m_cbPROpaqueBuf = 0;

        if (m_poAppContext != nullptr)
        {
            Drm_Uninitialize(m_poAppContext);
            SAFE_OEM_FREE(m_poAppContext);
            m_poAppContext = nullptr;
        }
    }

    dr = CPRDrmPlatform::DrmPlatformUninitialize();
    if (DRM_FAILED( dr )) {
        PR_LOG(PR_LOG_ERROR, "failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
    } else {
        PR_LOG(PR_LOG_DEBUG, "exit success");
    }
}

DRM_APP_CONTEXT * PlayreadySession::InitializeDRM(const DRM_CONST_STRING * pDRMStoreName)
{
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_VOID *pDrmOemContext = nullptr;
    
    PR_LOG(PR_LOG_DEBUG, "entry");

    SafeCriticalSection systemLock(prSessionMutex_);

    m_bInitCalled = true;

    if (m_poAppContext == nullptr)
    {
        PR_LOG(PR_LOG_INFO, "m_poAppContext is null");
        ChkMem( m_pbPROpaqueBuf = (DRM_BYTE *)Oem_MemAlloc(MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE) );
        ZEROMEM(m_pbPROpaqueBuf, MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE);
        m_cbPROpaqueBuf = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;

        ChkMem( m_poAppContext = (DRM_APP_CONTEXT * )Oem_MemAlloc( sizeof(DRM_APP_CONTEXT) ) );
        ZEROMEM( m_poAppContext, sizeof(DRM_APP_CONTEXT) );

        svpGetDrmOEMContext(&pDrmOemContext);

        PR_LOG(PR_LOG_INFO, "call Drm_Initialize()");
        dr = Drm_Initialize(m_poAppContext, pDrmOemContext, m_pbPROpaqueBuf, m_cbPROpaqueBuf, pDRMStoreName);
        if (dr != DRM_SUCCESS)
        {
            PR_LOG(PR_LOG_INFO, "Drm_Initialize failed. 0x%X - %s and try one more time...",dr,DRM_ERR_NAME(dr));
            ChkDR(Drm_Initialize(m_poAppContext, pDrmOemContext, m_pbPROpaqueBuf, m_cbPROpaqueBuf, pDRMStoreName));
        }
    }
    else
    {
        PR_LOG(PR_LOG_INFO, "m_poAppContext is valid but re-init again...");
        dr = Drm_Reinitialize(m_poAppContext);
        if (DRM_FAILED(dr))
        {
            PR_LOG(PR_LOG_ERROR, "Drm_Reinitialize failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
        }
    }

ErrorExit:
    if (DRM_FAILED(dr)) {
        PR_LOG(PR_LOG_ERROR, "InitializeDRM failed. 0x%X - %s ",dr,DRM_ERR_NAME(dr));
        m_poAppContext = nullptr;
    } else {
        PR_LOG(PR_LOG_DEBUG, "exit success");
    }
  return m_poAppContext;
}

MediaKeySession::MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, DRM_APP_CONTEXT * poAppContext, bool initiateChallengeGeneration /* = false */)
    : m_pbRevocationBuffer(nullptr)
    , m_eKeyState(KEY_CLOSED)
    , m_pbChallenge(nullptr)
    , m_cbChallenge(0)
    , m_pchSilentURL(nullptr) 
    , m_customData(reinterpret_cast<const char*>(f_pbCDMData), f_cbCDMData)
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
    , m_fCommit(FALSE)
    , m_poAppContext(poAppContext)
    , m_decryptInited(false)
    , m_bDRMInitializedLocally(false)
{
    DRM_RESULT          dr            = DRM_SUCCESS;
    DRM_ID              oSessionID    = DRM_ID_EMPTY;
    DRM_CONST_STRING    dstrWRMHEADER = DRM_EMPTY_DRM_STRING;
    DRM_DWORD cchEncodedSessionID = SIZEOF(m_rgchSessionID);
    PlayreadyInitDataType initDataType = PlayreadyInitDataType::PR_INIT_DATA_INVALID;

    PR_LOG(PR_LOG_DEBUG, "entry");

#ifdef USE_SVP
    gst_svp_ext_get_context(&m_pSVPContext, Client, 0);

    m_stSecureBuffInfo.bCreateSecureMemRegion = true;
    m_stSecureBuffInfo.SecureMemRegionSize = 512 * 1024;

    if( 0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, m_stSecureBuffInfo.SecureMemRegionSize))
    {
        /* No need to break here */
        m_stSecureBuffInfo.SecureMemRegionSize = 0;
    }
#endif

    std::string initData(reinterpret_cast<const char*>(f_pbInitData), f_cbInitData);
    std::string playreadyInitData;
    SafeCriticalSection systemLock(drmAppContextMutex_);

    ChkBOOL(m_eKeyState == KEY_CLOSED, DRM_E_INVALIDARG);

    mMaxResDecodePixels = 0;
    mMaxResDecodeSet = false;

    if (m_poAppContext == nullptr) {
        PR_LOG(PR_LOG_INFO, "m_poAppContext is not valid, calling InitializeDRM...");
        m_poAppContext = InitializeDRM(&g_dstrCDMDrmStoreName);
        if (m_poAppContext == nullptr) {
            goto ErrorExit;
        }
    }

    if (DRM_REVOCATION_IsRevocationSupported()) {
        PR_LOG(PR_LOG_INFO, "DRM Revocation is Supported");
        ChkMem(m_pbRevocationBuffer = (DRM_BYTE *)Oem_MemAlloc(REVOCATION_BUFFER_SIZE));

        ChkDR(Drm_Revocation_SetBuffer(m_poAppContext,
                                    m_pbRevocationBuffer,
                                    REVOCATION_BUFFER_SIZE));
    }
        
    ChkDR(Oem_Random_GetBytes(nullptr, (DRM_BYTE *)&oSessionID, SIZEOF(oSessionID)));
    ZEROMEM(m_rgchSessionID, SIZEOF(m_rgchSessionID));

    ChkDR(DRM_B64_EncodeA((DRM_BYTE *)&oSessionID,
                            SIZEOF(oSessionID),
                        m_rgchSessionID,
                        &cchEncodedSessionID,
                        0));

    initDataType = parsePlayreadyInitializationData(initData, &playreadyInitData);
    PR_LOG(PR_LOG_INFO, "initDataType[%u]", initDataType);

    switch(initDataType) {
        case PlayreadyInitDataType::PR_INIT_DATA_DRM_HEADER:
        case PlayreadyInitDataType::PR_INIT_DATA_PRO: {

            mDrmHeader.resize( playreadyInitData.size() );

            ::memcpy( &mDrmHeader[ 0 ],
                    reinterpret_cast<const DRM_BYTE*>(playreadyInitData.data()),
                    playreadyInitData.size() );

            std::string base64Header = convertToBase64(mDrmHeader);
            PR_LOG(PR_LOG_TRACE, "DRM Header size[%u] (String):[%s]",mDrmHeader.size(), base64Header.c_str());

            ChkDR(Drm_Content_SetProperty(m_poAppContext,
                            DRM_CSP_AUTODETECT_HEADER,
                            &mDrmHeader[ 0 ],
                            mDrmHeader.size()) );

            mInitiateChallengeGeneration = true;
        }
        break;
        default:
            mInitiateChallengeGeneration = false;
        break;
    }

    PR_LOG(PR_LOG_TRACE, "mInitiateChallengeGeneration[%d]", mInitiateChallengeGeneration);

    if(mInitiateChallengeGeneration) {

        DRM_CONST_DSTR_FROM_PB( &dstrWRMHEADER, &mDrmHeader[ 0 ], mDrmHeader.size() );
        ChkDR( Header_GetInfo( &dstrWRMHEADER,
                                            &m_eHeaderVersion,
                                            &m_pdstrHeaderKIDs,
                                            &m_cHeaderKIDs ) );

        PR_LOG(PR_LOG_INFO, "m_cHeaderKIDs[%d]", m_cHeaderKIDs);
        for( DRM_DWORD idx = 0; idx < m_cHeaderKIDs; idx++ )
        {
            KeyId kid , kid2;
            DRM_DWORD cBytes = DRM_ID_SIZE;
            DRM_DWORD cBytes2 = DRM_ID_SIZE;

            DRM_RESULT dr = DRM_B64_DecodeW( &m_pdstrHeaderKIDs[ idx ], &cBytes, kid.getmBytes(), 0 );
            if ( dr == DRM_SUCCESS )
            {
                kid.setKeyIdOrder(KeyId::KEYID_ORDER_GUID_LE);
            }

            DRM_RESULT dr2 = DRM_B64_DecodeW( &m_pdstrHeaderKIDs[ idx ], &cBytes2, kid2.getmBytes(), 0 );
            if ( dr2 == DRM_SUCCESS )
            {
                kid2.setKeyIdOrder(KeyId::KEYID_ORDER_GUID_LE);
            }
        }
    }

    m_eKeyState = KEY_INIT;

ErrorExit:

    if (DRM_FAILED(dr)) {
        m_eKeyState = KEY_ERROR;
        PR_LOG(PR_LOG_ERROR, "failed. 0x%X - %s ",dr,DRM_ERR_NAME(dr));
    } else {
        PR_LOG(PR_LOG_DEBUG, "exit success");
    }
    return;
}

MediaKeySession::~MediaKeySession(void)
{
    PR_LOG(PR_LOG_DEBUG, "entry");
    mMaxResDecodePixels = 0;
    mMaxResDecodeSet = false;
    Close();
    PR_LOG(PR_LOG_DEBUG, "exit");
}

const char* MediaKeySession::printGuid(KeyId &keyId)
{
    if (keyId.getKeyIdOrder() == KeyId::KEYID_ORDER_UUID_BE)
           keyId.ToggleFormat();
        return keyId.B64Str();
}

const char* MediaKeySession::printUuid(KeyId &keyId)
{
    if (keyId.getKeyIdOrder() == KeyId::KEYID_ORDER_GUID_LE)
           keyId.ToggleFormat();
        return keyId.B64Str();
}

const char *MediaKeySession::GetSessionId(void) const {
  return m_rgchSessionID;
}

const char *MediaKeySession::GetKeySystem(void) const {
  return NYI_KEYSYSTEM;
}

DRM_RESULT DRM_CALL MediaKeySession::_PolicyCallback(
    const DRM_VOID *f_pvOutputLevelsData, 
    DRM_POLICY_CALLBACK_TYPE f_dwCallbackType,
    const DRM_KID *f_pKID,
    const DRM_LID *f_pLID,
    const DRM_VOID *f_pv) {
    DRM_RESULT res = DRM_SUCCESS;

    PR_LOG(PR_LOG_DEBUG, "entry");

    switch (f_dwCallbackType)
    {
        case DRM_PLAY_OPL_CALLBACK:
        {
            PR_LOG(PR_LOG_INFO, "Type DRM_PLAY_OPL_CALLBACK");
            const DRM_PLAY_OPL_LATEST * const opl = static_cast<const DRM_PLAY_OPL_LATEST *>(f_pvOutputLevelsData);
            assert(opl->dwVersion == VER_DRM_PLAY_OPL_LATEST);

            /* MaxResDecode */
            const DRM_DIGITAL_VIDEO_OUTPUT_PROTECTION_IDS_LATEST &dvopi = opl->dvopi;
            assert(dvopi.dwVersion == VER_DRM_DIGITAL_VIDEO_OUTPUT_PROTECTION_IDS_LATEST);
            for (size_t i = 0; i < dvopi.cEntries; ++i)
            {
                const DRM_OUTPUT_PROTECTION_LATEST &entry = dvopi.rgVop[i];
                if (DRM_IDENTICAL_GUIDS(&entry.guidId, &g_guidMaxResDecode))
                {
                    assert(entry.dwVersion == VER_DRM_DIGITAL_VIDEO_OUTPUT_PROTECTION_LATEST);

                    uint32_t mrdWidth = (uint32_t)(entry.rgbConfigData[0] << 24 | entry.rgbConfigData[1] << 16 | entry.rgbConfigData[2] << 8 | entry.rgbConfigData[3]);
                    uint32_t mrdHeight = (uint32_t)(entry.rgbConfigData[4] << 24 | entry.rgbConfigData[5] << 16 | entry.rgbConfigData[6] << 8 | entry.rgbConfigData[7]);
                    

                    mMaxResDecodePixels = mrdWidth*mrdHeight;
                    mMaxResDecodeSet = true;
                    res = DRM_SUCCESS;
                    break;
                }
            }
            break;
        }
        default:
            // ignored
            PR_LOG(PR_LOG_INFO, "Type[%u] is not implemented!", f_dwCallbackType);
            res = DRM_SUCCESS;
            break;
    }

    PR_LOG(PR_LOG_DEBUG, "exit 0x%X - %s ",res,DRM_ERR_NAME(res));
    return res;
}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {

    PR_LOG(PR_LOG_DEBUG, "entry");

    if (f_piMediaKeySessionCallback) {
        PR_LOG(PR_LOG_INFO, "MediaKeySessionCallback valid. mInitiateChallengeGeneration[%d]", mInitiateChallengeGeneration);

        m_piCallback = const_cast<IMediaKeySessionCallback *>(f_piMediaKeySessionCallback);

        if (mInitiateChallengeGeneration) {
            PR_LOG(PR_LOG_INFO, "Call PersistentLicenseCheck...");
            if ( CDMi_SUCCESS != PersistentLicenseCheck() ) {
                PR_LOG(PR_LOG_INFO, "PersistentLicenseCheck failed and invoke playreadyGenerateKeyRequest");
                playreadyGenerateKeyRequest();
            } else {
                PR_LOG(PR_LOG_INFO, "PersistentLicenseCheck is success");
            }
        }
    } else {
        m_piCallback = nullptr;
    }

    PR_LOG(PR_LOG_DEBUG, "exit");
}

bool MediaKeySession::playreadyGenerateKeyRequest() {

  SafeCriticalSection systemLock(drmAppContextMutex_);
  DRM_RESULT dr = DRM_SUCCESS;
  DRM_DWORD cchSilentURL = 0;

  PR_LOG(PR_LOG_DEBUG, "entry");

  SAFE_OEM_FREE( m_pbChallenge );
  SAFE_OEM_FREE( m_pchSilentURL );

  m_cbChallenge = 0;

  ChkDR(Drm_Content_SetProperty(m_poAppContext,
                                DRM_CSP_AUTODETECT_HEADER,
                                &mDrmHeader[ 0 ],
                                mDrmHeader.size()) );

  dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                        g_rgpdstrRights,
                                        sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                        nullptr,
                                        !m_customData.empty() ? m_customData.c_str() : nullptr,
                                        m_customData.size(),
                                        nullptr,
                                        &cchSilentURL,
                                        nullptr,
                                        nullptr,
                                        m_pbChallenge,
                                        &m_cbChallenge,
                                        &m_oBatchID );

  if ( dr == DRM_E_NO_URL )
  {
    PR_LOG(PR_LOG_INFO, "License URL not present");
    dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                    g_rgpdstrRights,
                                    sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                    nullptr,
                                    !m_customData.empty() ? m_customData.c_str() : nullptr,
                                        m_customData.size() ,
                                    nullptr,
                                    nullptr,  // null pointer to buffer size
                                    nullptr,
                                    nullptr,
                                    m_pbChallenge,
                                    &m_cbChallenge,
                                    &m_oBatchID );
}

  if (dr == DRM_E_BUFFERTOOSMALL)
  {
    PR_LOG(PR_LOG_INFO, "challenge buffer is small, required size is %u", m_cbChallenge);
    if (cchSilentURL > 0)
    {
      ChkMem( m_pchSilentURL = (DRM_CHAR * )Oem_MemAlloc(cchSilentURL + 1));
      ZEROMEM( m_pchSilentURL, cchSilentURL + 1 );
    }

    if ( m_cbChallenge > 0 )
    {
      PR_LOG(PR_LOG_INFO, "reallocate the required buffer %u", m_cbChallenge);
      ChkMem( m_pbChallenge = (DRM_BYTE * )Oem_MemAlloc( m_cbChallenge + 1 ) );
      ZEROMEM( m_pbChallenge, m_cbChallenge + 1 );
    }

    dr = DRM_SUCCESS;
  }
  else
  {
    ChkDR(dr);
  }

  PR_LOG(PR_LOG_INFO, "call Drm_LicenseAcq_GenerateChallenge");
  ChkDR(Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                         g_rgpdstrRights,
                                         sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                         NULL,
                                         !m_customData.empty() ? m_customData.c_str() : nullptr,
                                         m_customData.size(),
                                         m_pchSilentURL,
                                         cchSilentURL ? &cchSilentURL : nullptr,
                                         nullptr,
                                         nullptr,
                                         m_pbChallenge,
                                         &m_cbChallenge,
                                         &m_oBatchID ) );


  m_eKeyState = KEY_PENDING;

  if (m_piCallback) {
    m_piCallback->OnKeyMessage((const uint8_t *) m_pbChallenge, m_cbChallenge,
                m_pchSilentURL != NULL ? (char *)m_pchSilentURL : "" );
    PR_LOG(PR_LOG_DEBUG, "Notified the challenge data message");
  }

ErrorExit:
  if (DRM_FAILED(dr)) {
    PR_LOG(PR_LOG_ERROR, "failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));

    if(m_piCallback)
    {
      m_piCallback->OnError( 0, CDMi_S_FALSE, "KeyError" );
      PR_LOG(PR_LOG_DEBUG, "Notified the KeyError message");
      m_piCallback->OnKeyStatusUpdate(MapDrToKeyMessage(dr), nullptr, 0);
      m_piCallback->OnKeyStatusesUpdated();
      PR_LOG(PR_LOG_DEBUG, "Notified the Keystatus updated message");
    }
    m_eKeyState = KEY_ERROR;
  } else {
    PR_LOG(PR_LOG_DEBUG, "success");
  }

  return ( dr == DRM_SUCCESS );
}

CDMi_RESULT MediaKeySession::Load(void) {
  PR_LOG(PR_LOG_DEBUG, "Not implemented");
  return CDMi_S_FALSE;
}

/*Set KeyId property which will be used by the Reader_Bind during license searching*/
CDMi_RESULT MediaKeySession::SetKeyIdProperty( const DRM_WCHAR *f_rgwchEncodedKid, DRM_DWORD f_cchEncodedKid ){
    PR_LOG(PR_LOG_DEBUG, "entry");

    DRM_RESULT err = Drm_Content_SetProperty(
            m_poAppContext,
            DRM_CSP_SELECT_KID,
            (DRM_BYTE*)f_rgwchEncodedKid,
            f_cchEncodedKid * sizeof( DRM_WCHAR ) );

    if (DRM_FAILED(err)) {
        PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty DRM_CSP_SELECT_KID failed. 0x%X - %s",err,DRM_ERR_NAME(err));
        return CDMi_FAIL;
    } else {
        PR_LOG(PR_LOG_DEBUG, "success");
    }

    return CDMi_SUCCESS;
}

/*Converting KeyId into base64-encoded format*/
CDMi_RESULT MediaKeySession::SetKeyIdProperty( KeyId & f_rKeyId ){
    DRM_WCHAR rgwchEncodedKid[CCH_BASE64_EQUIV(DRM_ID_SIZE)]= {0};
    DRM_DWORD cchEncodedKid = CCH_BASE64_EQUIV(DRM_ID_SIZE);

    PR_LOG(PR_LOG_DEBUG, "entry");

    if ( f_rKeyId.getKeyIdOrder() == KeyId::KEYID_ORDER_UUID_BE )
    {
        f_rKeyId.ToggleFormat();
    }

    DRM_RESULT err = DRM_B64_EncodeW( f_rKeyId.getmBytes(), DRM_ID_SIZE,
            rgwchEncodedKid, &cchEncodedKid, 0);

    if (DRM_FAILED(err)) {
        PR_LOG(PR_LOG_ERROR, "DRM_B64_EncodeW failed. 0x%X - %s",err,DRM_ERR_NAME(err));
        return CDMi_FAIL;
    }
    return SetKeyIdProperty( rgwchEncodedKid, cchEncodedKid );
}

/*handles all the licenses in the response using Drm_LicenseAcq_ProcessResponse().*/
DRM_RESULT MediaKeySession::ProcessLicenseResponse(
                DRM_PROCESS_LIC_RESPONSE_FLAG    f_eResponseFlag,
        const   DRM_BYTE                        *f_pbResponse,
                DRM_DWORD                        f_cbResponse,
                DRM_LICENSE_RESPONSE            *f_pLiceneResponse ) {
    DRM_RESULT dr = DRM_SUCCESS;
    PR_LOG(PR_LOG_DEBUG, "entry");
    dr = Drm_LicenseAcq_ProcessResponse(
            m_poAppContext,
            f_eResponseFlag,
            f_pbResponse,
            f_cbResponse,
            f_pLiceneResponse );

    if ( dr == DRM_E_LICACQ_TOO_MANY_LICENSES )
    {
        PR_LOG(PR_LOG_INFO, "Too many licenses present in the response");
        DRM_DWORD cLicenses = f_pLiceneResponse->m_cAcks;
        f_pLiceneResponse->m_pAcks = ( DRM_LICENSE_ACK * )Oem_MemAlloc( cLicenses * sizeof( DRM_LICENSE_ACK ) );
        f_pLiceneResponse->m_cMaxAcks = cLicenses;

        dr = Drm_LicenseAcq_ProcessResponse(
                m_poAppContext,
                f_eResponseFlag,
                f_pbResponse,
                f_cbResponse,
                f_pLiceneResponse );
    }

    PR_LOG(PR_LOG_DEBUG, "result: 0x%X - %s",dr,DRM_ERR_NAME(dr));
    return dr;
}

/*Wrapper function for Drm_Reader_Bind()*/
DRM_RESULT MediaKeySession::ReaderBind(
            const DRM_CONST_STRING *f_rgpdstrRights[],
            DRM_DWORD f_cRights,
            DRMPFNPOLICYCALLBACK  f_pfnPolicyCallback,
            const DRM_VOID             *f_pv,
            DRM_DECRYPT_CONTEXT *f_pDecryptContext ) {
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_BYTE *newOpaqueBuffer = nullptr;

    PR_LOG(PR_LOG_DEBUG, "entry");

    while( (dr=Drm_Reader_Bind(
                    m_poAppContext,
                    f_rgpdstrRights,
                    f_cRights,
                    f_pfnPolicyCallback,
                    f_pv,
                    f_pDecryptContext ) ) == DRM_E_BUFFERTOOSMALL ){
                    

        DRM_BYTE *pbOldBuf = nullptr;
        DRM_DWORD cbOldBuf = 0;

        if ( m_cbPROpaqueBuf == 0 )
            m_cbPROpaqueBuf = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;

        m_cbPROpaqueBuf *= 2;

        if ( m_cbPROpaqueBuf > MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE * 64 ){
            ChkDR( DRM_E_OUTOFMEMORY );
        }

        ChkMem( newOpaqueBuffer = ( DRM_BYTE* )Oem_MemAlloc( m_cbPROpaqueBuf ) );

        dr = Drm_GetOpaqueBuffer( m_poAppContext, &pbOldBuf, &cbOldBuf );
        if ( DRM_FAILED( dr ) ){
            fprintf(stderr, "[%s:%d] Drm_GetOpaqueBuffer failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            SAFE_OEM_FREE( newOpaqueBuffer );
            ChkDR( dr );
        }

        dr = Drm_ResizeOpaqueBuffer( m_poAppContext, newOpaqueBuffer, m_cbPROpaqueBuf );
        if ( DRM_FAILED( dr ) ){
            fprintf(stderr, "[%s:%d] Drm_ResizeOpaqueBuffer failed. 0x%X - %s",__FUNCTION__,__LINE__,dr,DRM_ERR_NAME(dr));
            SAFE_OEM_FREE( newOpaqueBuffer );
            ChkDR( dr );
        }

        if ( m_pbPROpaqueBuf != nullptr && m_pbPROpaqueBuf == pbOldBuf ){
            SAFE_OEM_FREE( pbOldBuf );
            m_pbPROpaqueBuf = newOpaqueBuffer;
        }else{
            SAFE_OEM_FREE( pbOldBuf );
        }
    }

ErrorExit:
    if ( DRM_FAILED( dr ) ){
        PR_LOG(PR_LOG_ERROR, "result: 0x%X - %s",dr,DRM_ERR_NAME(dr));
    } else {
        PR_LOG(PR_LOG_DEBUG, "success: 0x%X", dr);
    }

    return dr;
}

CDMi_RESULT MediaKeySession::PersistentLicenseCheck() {
    SafeCriticalSection systemLock(drmAppContextMutex_);
#ifdef NO_PERSISTENT_LICENSE_CHECK
    // DELIA-51437: The Webkit EME implementation used by OTT apps
    // such as Amazon and YouTube fails when the key is usable from
    // just the init data.  Webkit is expecting a license request
    // message and the lack of this message prevents the session from
    // loading correctly.
    //
    // The EME concept of a persistent session uses the Session Id to
    // reload a session, not the raw Key ID.  We do not current
    // support that type of session in the OCDM.  Apps wishing to use
    // persistent keys should directly link to PR4 or the OCDM should
    // be rewritten to use PR4's CDMI API
    // (modules/cdmi/real/drmcdmireal.c).
    PR_LOG(PR_LOG_DEBUG, "PersistentLicenseCheck: not supported");
    return CDMi_S_FALSE;
#else
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_CONTENT_SET_PROPERTY eContentPropertyType = DRM_CSP_HEADER_NOT_SET;

    if ( !mDrmHeader.size() ) {
        fprintf(stderr, "[%s:%d] mDrmHeader not set",__FUNCTION__,__LINE__);
        return CDMi_FAIL;
    }
    if ( m_pdstrHeaderKIDs == NULL || m_cHeaderKIDs == 0 ){
        fprintf(stderr, "[%s:%d] key ids not set",__FUNCTION__,__LINE__);
        return CDMi_FAIL;
    }

    if ( m_eHeaderVersion == DRM_HEADER_VERSION_4_2 )
        eContentPropertyType = DRM_CSP_V4_2_HEADER;
    else if ( m_eHeaderVersion == DRM_HEADER_VERSION_4_3 )
        eContentPropertyType = DRM_CSP_V4_3_HEADER;
    else{
        eContentPropertyType = DRM_CSP_AUTODETECT_HEADER;
    }

    for( DRM_DWORD idx = 0; idx < m_cHeaderKIDs; idx++ ){

        KeyId keyId;
		keyId.keyDecode(m_pdstrHeaderKIDs[ idx ]);
        keyId.setKeyIdOrder(KeyId::KEYID_ORDER_GUID_LE);

        DECRYPT_CONTEXT decryptContext;

        if ( CDMi_SUCCESS != SetKeyIdProperty( m_pdstrHeaderKIDs[idx].pwszString,
                m_pdstrHeaderKIDs[idx].cchString ) ) {
            fprintf(stderr, "[%s:%d] SetKeyIdProperty failed. %s",__FUNCTION__,__LINE__,printGuid(keyId));
            ChkDR( DRM_E_FAIL );
        }

        decryptContext = NEW_DECRYPT_CONTEXT();

        dr = ReaderBind(
                    g_rgpdstrRights,
                    NO_OF(g_rgpdstrRights),
                    _PolicyCallback,
                    &m_playreadyLevels,
                    &(decryptContext->oDrmDecryptContext) );
        if ( DRM_FAILED( dr ) ){
            ChkDR( dr );
        }

        decryptContext->keyId = keyId;
        m_DecryptContextVector.push_back(decryptContext);
    }

ErrorExit:

    if ( DRM_FAILED( dr ) ){
        CloseDecryptContexts();
        return CDMi_FAIL;
    }

    if ( m_piCallback )
    {
        for (DECRYPT_CONTEXT &p : m_DecryptContextVector)
        {
            m_piCallback->OnKeyStatusUpdate(MapDrToKeyMessage( dr ), (const uint8_t *)p->keyId.getmBytes(), DRM_ID_SIZE);
        }
        m_piCallback->OnKeyStatusesUpdated();
    }

    m_eKeyState = KEY_READY;

    return CDMi_SUCCESS;
#endif
}

// Allow persistent PlayReady licenses to be used in a temporary
// session.
//
// Ideally, the license server would only return temporary licenses
// and would could block all persistent license with the
// `DRM_PROCESS_LIC_RESPONSE_FLAG` value of
// `DRM_PROCESS_LIC_RESPONSE_BLOCK_PERSISTENT_LICENSES`.
//
// Instead, we allow persistent licenses to be used but attempt to
// clean them up when the session closes.
void MediaKeySession::SaveTemporaryPersistentLicenses(const DRM_LICENSE_RESPONSE* f_poLicenseResponse) {

    PR_LOG(PR_LOG_DEBUG, "entry");

    for(;;)
    {
        if(f_poLicenseResponse == NULL) {
            PR_LOG(PR_LOG_ERROR, "License Response is null");
            break;
        }

        PR_LOG(PR_LOG_DEBUG, "response has PersistentLicenses[%d]", f_poLicenseResponse->m_fHasPersistentLicenses);

        if (!f_poLicenseResponse->m_fHasPersistentLicenses) {
          break;
        }

        PR_LOG(PR_LOG_DEBUG, "No of licenses [%d]", f_poLicenseResponse->m_cAcks);

        // We know there are persistent license but not which ones.  Save
        // them all for deletion when we close a session.
        for (DRM_DWORD i = 0; i < f_poLicenseResponse->m_cAcks; ++i) {
            const DRM_LICENSE_ACK *pLicenseAck = nullptr;

            pLicenseAck = f_poLicenseResponse->m_pAcks != nullptr
                ? &f_poLicenseResponse->m_pAcks[ i ] : &f_poLicenseResponse->m_rgoAcks[ i ];

            if ( DRM_SUCCEEDED( pLicenseAck->m_dwResult ) ) {
                m_oPersistentLicenses.emplace_back(pLicenseAck->m_oKID, pLicenseAck->m_oLID);
            }
        }

        break;
    }

    PR_LOG(PR_LOG_DEBUG, "exit");
    return;
}

void MediaKeySession::DeleteTemporaryPersistentLicenses() {
    DRM_RESULT dr = DRM_SUCCESS;
    DRM_CONST_STRING          dstrKID              = DRM_EMPTY_DRM_STRING;
    DRM_CONST_STRING          dstrLID              = DRM_EMPTY_DRM_STRING;
    DRM_DWORD                 cbstrKID             = 0;
    DRM_DWORD cLicDeleted = 0;

    PR_LOG(PR_LOG_DEBUG, "entry");

    if(m_oPersistentLicenses.empty()) {
        PR_LOG(PR_LOG_DEBUG, "There is no persistentLicenses");
        goto ErrorExit;
    }

    /* Allocate strKID buffer */
    cbstrKID = CCH_BASE64_EQUIV( sizeof( DRM_ID ) ) * sizeof( DRM_WCHAR );
    ChkMem( dstrKID.pwszString = (DRM_WCHAR *) Oem_MemAlloc( cbstrKID ) );
    dstrKID.cchString = CCH_BASE64_EQUIV( sizeof( DRM_ID ) );

    ChkMem( dstrLID.pwszString = (DRM_WCHAR *) Oem_MemAlloc( cbstrKID ) );
    dstrLID.cchString = CCH_BASE64_EQUIV( sizeof( DRM_ID ) );

    for (const auto& pair: m_oPersistentLicenses) {

        /* Convert KID to string */
        dr = DRM_B64_EncodeW(
            (DRM_BYTE*)&pair.first,
            sizeof( DRM_ID ),
            (DRM_WCHAR*)dstrKID.pwszString,
            &dstrKID.cchString,
            DRM_BASE64_ENCODE_NO_FLAGS );

        if (DRM_FAILED(dr)) {
            PR_LOG(PR_LOG_DEBUG, "DRM_B64_EncodeW failed: 0x%X - %s",dr,DRM_ERR_NAME(dr));
            continue;
        }

        /* Convert LID to string */
        dr = DRM_B64_EncodeW(
            (DRM_BYTE*)&pair.second,
            sizeof( DRM_ID ),
            (DRM_WCHAR*)dstrLID.pwszString,
            &dstrKID.cchString,
            DRM_BASE64_ENCODE_NO_FLAGS );

        if (DRM_FAILED(dr)) {
            PR_LOG(PR_LOG_DEBUG, "DRM_B64_EncodeW failed: 0x%X - %s",dr,DRM_ERR_NAME(dr));
            continue;
        }

        dr = Drm_StoreMgmt_DeleteLicenses(
            m_poAppContext,
            &dstrKID,
            &dstrLID,
            &cLicDeleted);

    }

ErrorExit:
    SAFE_OEM_FREE( dstrKID.pwszString );
    SAFE_OEM_FREE( dstrLID.pwszString );
    if ( DRM_FAILED( dr ) ){
        PR_LOG(PR_LOG_ERROR, "failed: 0x%X - %s",dr,DRM_ERR_NAME(dr));
    } else {
        PR_LOG(PR_LOG_DEBUG, "success: 0x%X", dr);
    }
    return;
}

/*processes the license response and creates decryptor for each valid ack available in the response*/
void MediaKeySession::Update(const uint8_t *m_pbKeyMessageResponse, uint32_t  m_cbKeyMessageResponse) {

    SafeCriticalSection systemLock(drmAppContextMutex_);

    DRM_RESULT dr = DRM_SUCCESS;
    DRM_LICENSE_RESPONSE oLicenseResponse = { eUnknownProtocol, 0 };
    DRM_LICENSE_ACK *pLicenseAck = nullptr;
    DRM_DWORD decryptionMode;
    bool bIsAudioNeedNonSVPContext;
    
    PR_LOG(PR_LOG_DEBUG, "Entry");

    ChkBOOL(m_eKeyState == KEY_PENDING, DRM_E_INVALIDARG);

    ChkArg(m_pbKeyMessageResponse && m_cbKeyMessageResponse > 0);

    PR_LOG(PR_LOG_INFO, "call ProcessLicenseResponse");
    ChkDR( ProcessLicenseResponse(
            DRM_PROCESS_LIC_RESPONSE_NO_FLAGS,
            const_cast<DRM_BYTE *>(m_pbKeyMessageResponse),
            m_cbKeyMessageResponse,
            &oLicenseResponse ) );

    SaveTemporaryPersistentLicenses(&oLicenseResponse);

    for (DRM_DWORD i = 0; i < oLicenseResponse.m_cAcks; ++i) {

        pLicenseAck = oLicenseResponse.m_pAcks != nullptr
                ? &oLicenseResponse.m_pAcks[ i ] : &oLicenseResponse.m_rgoAcks[ i ];

        KeyId keyId(&pLicenseAck->m_oKID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);

        dr = pLicenseAck->m_dwResult;
        if ( DRM_SUCCEEDED( dr ) ) {

            DECRYPT_CONTEXT decryptContext;

            if ( CDMi_SUCCESS != SetKeyIdProperty( keyId ) )
            {
                dr = DRM_E_FAIL;
                goto LoopEnd;
            }

            PR_LOG(PR_LOG_DEBUG, "DRM Decrypt context created");
            decryptContext = NEW_DECRYPT_CONTEXT();

            decryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
            dr = Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                    (const DRM_BYTE*)&decryptionMode,
                                    sizeof decryptionMode);
            if (!DRM_SUCCEEDED(dr)) {
                PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty failed: 0x%X - %s",dr,DRM_ERR_NAME(dr));
                goto ErrorExit;
            }

            dr = ReaderBind(
                    g_rgpdstrRights,
                    NO_OF(g_rgpdstrRights),
                    _PolicyCallback,
                    &m_playreadyLevels,
                    &(decryptContext->oDrmDecryptContext) );

            if ( DRM_FAILED( dr ) ){
                PR_LOG(PR_LOG_ERROR, "ReaderBind failed: 0x%X - %s",dr,DRM_ERR_NAME(dr));
                goto LoopEnd;
            }

            bIsAudioNeedNonSVPContext = svpIsAudioNeedNonSVPContext();

            if(bIsAudioNeedNonSVPContext)
            {
              decryptionMode = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
              dr = Drm_Content_SetProperty(m_poAppContext,
                                      DRM_CSP_DECRYPTION_OUTPUT_MODE,
                                      (const DRM_BYTE*)&decryptionMode,
                                      sizeof decryptionMode);
              if (!DRM_SUCCEEDED(dr)) {
                  PR_LOG(PR_LOG_ERROR, "Drm_Content_SetProperty failed: 0x%X - %s",dr,DRM_ERR_NAME(dr));
                  goto ErrorExit;
              }

              dr = ReaderBind(
                      g_rgpdstrRights,
                      NO_OF(g_rgpdstrRights),
                      _PolicyCallback,
                      &m_playreadyLevels,
                      &(decryptContext->oDrmDecryptAudioContext) );

              if ( DRM_FAILED( dr ) ){
                  PR_LOG(PR_LOG_ERROR, "ReaderBind failed: 0x%X - %s",dr,DRM_ERR_NAME(dr));
                  goto LoopEnd;
              }
            }

            decryptContext->keyId = keyId;

            if ( oLicenseResponse.m_cAcks == 1 ){
                m_currentDecryptContext = decryptContext;
            }

            m_DecryptContextVector.push_back(decryptContext);

            m_eKeyState = KEY_READY;
        }
    LoopEnd:
        if ( m_piCallback ){
            m_piCallback->OnKeyStatusUpdate( MapDrToKeyMessage( dr ), (const uint8_t *)keyId.getmBytes(), DRM_ID_SIZE);
            PR_LOG(PR_LOG_DEBUG, "Notified keystatus update message");
        }
    } 

    if ( m_eKeyState == KEY_READY ){
        dr = DRM_SUCCESS;
    }else{
        PR_LOG(PR_LOG_ERROR, "Could not bind to any licenses. m_eKeyState[%u]", m_eKeyState);
        dr = DRM_E_FAIL;
    }

ErrorExit:
    if (DRM_FAILED(dr)) {
        PR_LOG(PR_LOG_ERROR, "result: 0x%X - %s",dr,DRM_ERR_NAME(dr));
        m_eKeyState = KEY_ERROR;
    } else {
        PR_LOG(PR_LOG_DEBUG, "success: 0x%X", dr);
    }

    if (m_piCallback){
        m_piCallback->OnKeyStatusesUpdated();
        PR_LOG(PR_LOG_DEBUG, "Notified keystatus updated message");
    }
    SAFE_OEM_FREE( oLicenseResponse.m_pAcks );

    PR_LOG(PR_LOG_DEBUG, "exit");
  return;
}

CDMi_RESULT MediaKeySession::Remove(void) {
  PR_LOG(PR_LOG_DEBUG, "Not implemented");
  return CDMi_S_FALSE;
}

/*Closes each DRM_DECRYPT_CONTEXT using Drm_Reader_Close()*/
void MediaKeySession::CloseDecryptContexts(void) {
    m_currentDecryptContext = nullptr;

    PR_LOG(PR_LOG_DEBUG, "entry");

    for (DECRYPT_CONTEXT &p : m_DecryptContextVector)
    {
        Drm_Reader_Close(&(p->oDrmDecryptContext));
        Drm_Reader_Close(&(p->oDrmDecryptAudioContext));
    }
    m_DecryptContextVector.clear();
    PR_LOG(PR_LOG_DEBUG, "exit");
}

void MediaKeySession::DeleteInMemoryLicenses()  {
    DRM_ID emptyId = DRM_ID_EMPTY;

    PR_LOG(PR_LOG_DEBUG, "entry");

    if (memcmp(&m_oBatchID, &emptyId, sizeof(DRM_ID)) == 0) {
        return;
    }
    KeyId batchId(&m_oBatchID.rgb[0],KeyId::KEYID_ORDER_GUID_LE);

    DRM_RESULT dr = Drm_StoreMgmt_DeleteInMemoryLicenses(m_poAppContext, &m_oBatchID);
    if (DRM_FAILED(dr) && dr != DRM_E_NOMORE) {
        PR_LOG(PR_LOG_ERROR, "Drm_StoreMgmt_DeleteInMemoryLicenses failed for batchId:%s. 0x%X - %s",printUuid(batchId),dr,DRM_ERR_NAME(dr));
    } 
}

CDMi_RESULT MediaKeySession::Close(void) {
    PR_LOG(PR_LOG_DEBUG, "Entry m_eKeyState[%u]", m_eKeyState);

    SafeCriticalSection systemLock(drmAppContextMutex_);
    if ( m_eKeyState != KEY_CLOSED ) {
#ifdef USE_SVP
        m_stSecureBuffInfo.bReleaseSecureMemRegion = true;
        if(0 != svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, nullptr, nullptr, 0))
        {
            PR_LOG(PR_LOG_DEBUG, "svp_release_secure_buffers failed");
        }
        else {
            m_stSecureBuffInfo.bCreateSecureMemRegion = false;
            m_stSecureBuffInfo.SecureMemRegionSize = 0;
        }
        gst_svp_ext_free_context(m_pSVPContext);
        m_pSVPContext = NULL;
#endif

        SAFE_OEM_FREE(m_pbChallenge);

        SAFE_OEM_FREE(m_pchSilentURL);

        CloseDecryptContexts();

        DeleteInMemoryLicenses();

        DeleteTemporaryPersistentLicenses();

        mDrmHeader.clear();

        SAFE_OEM_FREE(m_pbRevocationBuffer);

        SAFE_OEM_FREE(m_pdstrHeaderKIDs);

        m_eKeyState = KEY_CLOSED;
    }

    PR_LOG(PR_LOG_DEBUG, "exit");
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::PlaybackStopped(void) {
  PR_LOG(PR_LOG_DEBUG, "Not implemented");
  return CDMi_SUCCESS;
}

const char* MediaKeySession::MapDrToKeyMessage( DRM_RESULT dr )
{
    PR_LOG(PR_LOG_DEBUG, "key message: 0x%X - %s",dr,DRM_ERR_NAME(dr));
    switch (dr)
    {
    case DRM_SUCCESS:
        return "KeyUsable";
    case DRM_E_TEE_OUTPUT_PROTECTION_REQUIREMENTS_NOT_MET:
    case DRM_E_TEST_OPL_MISMATCH:
        return "KeyOutputRestricted";
    case DRM_E_TEE_OUTPUT_PROTECTION_INSUFFICIENT_HDCP:
        return "KeyOutputRestrictedHDCP";
    case DRM_E_TEE_OUTPUT_PROTECTION_INSUFFICIENT_HDCP22:
    case DRM_E_TEST_INVALID_OPL_CALLBACK:
        return "KeyOutputRestrictedHDCP22";
    case DRM_E_LICENSE_NOT_FOUND:
        return "LicenseNotFound";
    case DRM_E_LICENSE_EXPIRED:
        return "LicenseExpired";
    default:
        return "KeyInternalError";
    }
}

CDMi_RESULT MediaKeySession::DRM_DecryptFailure(DRM_RESULT dr, const uint8_t *payloadData, uint32_t *f_pcbOpaqueClearContent, uint8_t **f_ppbOpaqueClearContent)
{
      PR_LOG(PR_LOG_DEBUG, "DRM_DecryptFailure: 0x%X - %s",dr,DRM_ERR_NAME(dr));

      if(f_pcbOpaqueClearContent != nullptr)
      {
          *f_pcbOpaqueClearContent = 0;
      }
      if(f_ppbOpaqueClearContent != nullptr && payloadData != nullptr)
      {
          *f_ppbOpaqueClearContent = (uint8_t *)payloadData;
      }

      if(m_piCallback){
          char errStr[50];
          uint64_t errCode = (0xFFFFFFFF00000000)|(dr);
          sprintf(errStr,"0x%llx-DecryptError",errCode);
          m_piCallback->OnError(0, CDMi_S_FALSE, errStr);
          m_piCallback->OnKeyStatusUpdate(MapDrToKeyMessage( dr ), nullptr, 0);
          m_piCallback->OnKeyStatusesUpdated();
      }
      return CDMi_S_FALSE;  
}

DECRYPT_CONTEXT MediaKeySession::GetDecryptCtx( KeyId &f_rKeyId )
{
    PR_LOG(PR_LOG_DEBUG, "entry");
    for (DECRYPT_CONTEXT &ctx : m_DecryptContextVector)
    {
        if (ctx->keyId == f_rKeyId)
        {
            PR_LOG(PR_LOG_DEBUG, "exit. ctx found");
            return ctx;
        }
    }
    PR_LOG(PR_LOG_ERROR, "exit. ctx not found");
    return nullptr;
}

CDMi_RESULT MediaKeySession::SetParameter(const std::string& name, const std::string& value)
{
  CDMi_RESULT retVal = CDMi_S_FALSE;
  PR_LOG(PR_LOG_DEBUG, "entry");

  if(name.find("rpcId") != std::string::npos) {
    // Got the RPC ID for gst-svp-ext communication
    unsigned int nID = 0;
    nID =  (unsigned int)std::stoul(value.c_str(), nullptr, 16);
    if(nID != 0) {
#ifdef USE_SVP
      //fprintf(stderr, "Initializing SVP context for client side ID = %X\n", nID);
      gst_svp_ext_get_context(&m_pSVPContext, Client, nID);
#endif
    }
  }
  return retVal;
}

CDMi_RESULT MediaKeySession::Decrypt(
        uint8_t*                 inData,
        const uint32_t           inDataLength,
        uint8_t**                outData,
        uint32_t*                outDataLength,
        const SampleInfo*        sampleInfo,
        const IStreamProperties* properties)
{
  DRM_RESULT err = DRM_SUCCESS;
  void* pSecureToken = nullptr;
  uint8_t* pEncryptedDataStart  = nullptr;
  uint32_t actualEncDataLength = 0;
  void* header = NULL;
  DRM_DWORD encryptedRegionIvCounts = 1;
  DRM_DWORD encryptedRegionCounts;
  std::vector<DRM_DWORD> encryptedRegionSkip;
  std::vector<DRM_DWORD> encryptedRegionMapping;
  bool bGstSvpStatus = false;
  bool useSVP = true; // By default SVP is required
  DRM_UINT64 iv_vector[2] = { 0 };
  bool bIsVideoResCheckNeed = false;
  bool bIsDynamicSVPEncEnabled = false;
  uint64_t mCurrentPixels;
  bool bIsAudioNeedNonSVPContext;
  bool bIsMultipleOpaqueSupportCTR = false;
  DRM_DWORD decryptedLength = 0;
  DRM_BYTE* pDecryptedContent = NULL;
  DRM_BYTE*  pEncryptedData = NULL;

  PR_LOG(PR_LOG_TRACE, "entry");
  PR_LOG(PR_LOG_TRACE, "inDataLength[%u]", inDataLength);

  if(sampleInfo == NULL) {
      PR_LOG(PR_LOG_ERROR, "sampleInfo is null");
      return CDMi_S_FALSE;
  }

  if (sampleInfo->ivLength != EXPECTED_AES_CTR_IVDATA_SIZE &&
      sampleInfo->ivLength != EXPECTED_AES_CBC_IVDATA_SIZE) {
      PR_LOG(PR_LOG_ERROR, "invalid ivLength %u", sampleInfo->ivLength);
      return CDMi_S_FALSE;
  }

  bIsVideoResCheckNeed = svpIsVideoResCheckNeed();

  if(bIsVideoResCheckNeed)
  {
    if (properties->GetMediaType() == Video) {
        mCurrentPixels = properties->GetHeight() * properties->GetWidth();
    }

    /* MaxResDecode */
    if (mMaxResDecodeSet) {
      if ((mCurrentPixels > mMaxResDecodePixels)) {
          PR_LOG(PR_LOG_ERROR, "video resolution:%llu exceeds maximum resolution:%lu",mCurrentPixels,mMaxResDecodePixels);
          return CDMi_S_FALSE;
      }
    }
  }

  bIsDynamicSVPEncEnabled = svpIsDynamicSVPEncEnabled();
  if(bIsDynamicSVPEncEnabled)
  {
    if (properties->GetMediaType() != Video) {
      useSVP = false;
    }
  }

  if ( sampleInfo->keyId != nullptr ){
      KeyId keyId(&sampleInfo->keyId[0],KeyId::KEYID_ORDER_UUID_BE);

      if (m_currentDecryptContext == nullptr
                || m_currentDecryptContext->keyId != keyId)
      {
          m_currentDecryptContext = GetDecryptCtx( keyId );
      }
  }

  if ( m_currentDecryptContext == nullptr ){
      PR_LOG(PR_LOG_ERROR, "m_currentDecryptContext is not valid");
      return CDMi_S_FALSE;
  }

  SafeCriticalSection systemLock(drmAppContextMutex_);

    // Regular case
    NETWORKBYTES_TO_QWORD(iv_vector[0], sampleInfo->iv, 0);
    if (sampleInfo->ivLength == 16) {
        NETWORKBYTES_TO_QWORD(iv_vector[1], sampleInfo->iv, 8);
    }


  if (gst_svp_has_header(m_pSVPContext, inData)) {
    header = (void*)inData;
    pEncryptedDataStart = reinterpret_cast<DRM_BYTE *>(gst_svp_header_get_start_of_data(m_pSVPContext, header));
    gst_svp_header_get_field(m_pSVPContext, header, SvpHeaderFieldName::DataSize, &actualEncDataLength);
    PR_LOG(PR_LOG_TRACE, "svp Header found actualDataLength[%u]", actualEncDataLength);
  } else {
    pEncryptedDataStart = inData;
    actualEncDataLength = inDataLength;
  }

  if(useSVP) {
    /* Ensure that actualEncDataLength has enough space to accommodate the SVP token. */
    if (actualEncDataLength < svp_token_size()) {
      PR_LOG(PR_LOG_ERROR, "Invalid encrypted data length %u (token size %u)", actualEncDataLength, svp_token_size());
      return CDMi_S_FALSE;
    }
  }

  PR_LOG(PR_LOG_TRACE, "subSampleCount [%u]", sampleInfo->subSampleCount);

  if (sampleInfo->subSampleCount > 0) {
    for (int i = 0; i < sampleInfo->subSampleCount; i++) {
      encryptedRegionMapping.push_back(sampleInfo->subSample[i].clear_bytes);
      encryptedRegionMapping.push_back(sampleInfo->subSample[i].encrypted_bytes);
    }
  } else {
      encryptedRegionMapping.push_back(0);
      encryptedRegionMapping.push_back(actualEncDataLength);
  }

  PR_LOG(PR_LOG_TRACE, "encryptedRegionMapping [%u]", encryptedRegionMapping.size());

  encryptedRegionCounts = encryptedRegionMapping.size()/2;

  PR_LOG(PR_LOG_TRACE, "encryptedRegionCounts [%u]", encryptedRegionCounts);

  if(useSVP)
  {
    PR_LOG(PR_LOG_TRACE, "bCreateSecureMemRegion [%d]", m_stSecureBuffInfo.bCreateSecureMemRegion);
    // Reallocate input memory if needed.
    if(m_stSecureBuffInfo.bCreateSecureMemRegion)
    {
        if (actualEncDataLength >  m_stSecureBuffInfo.SecureMemRegionSize) {
            m_stSecureBuffInfo.bReleaseSecureMemRegion = true;
            if(0 != svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, nullptr, nullptr, 0))
            {
                PR_LOG(PR_LOG_ERROR, "svp_release_secure_buffers failed ");
                return CDMi_S_FALSE;
            }
            m_stSecureBuffInfo.SecureMemRegionSize = actualEncDataLength;
            m_stSecureBuffInfo.bReleaseSecureMemRegion = false;

            if(0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, nullptr, m_stSecureBuffInfo.SecureMemRegionSize))
            {
                PR_LOG(PR_LOG_ERROR, "Secure memory, re-allocation failed %d", m_stSecureBuffInfo.SecureMemRegionSize);
                return CDMi_S_FALSE;
            }
        }
    }

    m_stSecureBuffInfo.patternClearBlocks = sampleInfo->pattern.clear_blocks;

    if(0 != svp_allocate_secure_buffers(m_pSVPContext, (void**)&m_stSecureBuffInfo, nullptr, pEncryptedDataStart, actualEncDataLength))
    {
        PR_LOG(PR_LOG_ERROR, "svp_allocate_secure_buffers failed %d", actualEncDataLength);
        return CDMi_S_FALSE;
    }

/* TO DO */
#if defined TEE_CONFIG_NEED
    OEM_OPTEE_SetHandle(m_stSecureBuffInfo.pSecBufHandle);
#endif /* TEE_CONFIG_NEED */

    bGstSvpStatus = svp_buffer_alloc_token(&pSecureToken);
    if (!bGstSvpStatus) {
        PR_LOG(PR_LOG_ERROR, "memory allocation for Token is failed %d", actualEncDataLength);
        m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
        // Free decrypted secure buffer.
        svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, (void*)m_stSecureBuffInfo.pAVSecBuffer , nullptr, 0);
        return CDMi_S_FALSE;
    }

    bGstSvpStatus = svp_buffer_to_token(m_pSVPContext, (void *)&m_stSecureBuffInfo, pSecureToken);
    if (!bGstSvpStatus) {
        PR_LOG(PR_LOG_ERROR, "Buffer to Token creation is failed");
        m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
        // Free decrypted secure buffer.
        svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, (void*)m_stSecureBuffInfo.pAVSecBuffer , nullptr, 0);
        svp_buffer_free_token(pSecureToken);
        return CDMi_S_FALSE;
    }
  }

    PR_LOG(PR_LOG_TRACE, "EncScheme [%u] encrypted_blocks[%d]", sampleInfo->scheme, sampleInfo->pattern.encrypted_blocks);

    if (sampleInfo->scheme == AesCbc_Cbcs) {
        // Always push the pattern for CBCS, even if it's 0:0 for Audio
        encryptedRegionSkip.push_back(sampleInfo->pattern.encrypted_blocks);
        encryptedRegionSkip.push_back(sampleInfo->pattern.clear_blocks);
    } else if (sampleInfo->pattern.encrypted_blocks != 0) {
        encryptedRegionSkip.push_back(sampleInfo->pattern.encrypted_blocks);
        encryptedRegionSkip.push_back(sampleInfo->pattern.clear_blocks);
    }

  if (useSVP)
  {
    decryptedLength = actualEncDataLength;
    pDecryptedContent = reinterpret_cast<DRM_BYTE*>(m_stSecureBuffInfo.pPhysAddr);
    pEncryptedData = reinterpret_cast<DRM_BYTE*>(m_stSecureBuffInfo.pEncryptedDataBuffer);
  }
  else
  {
      pEncryptedData = pEncryptedDataStart;
  }

  bIsMultipleOpaqueSupportCTR = svpIsMultipleOpaqueSupportCTR();

  PR_LOG(PR_LOG_TRACE, "bIsMultipleOpaqueSupportCTR [%u] ",bIsMultipleOpaqueSupportCTR);

  /* For Video */
  if (useSVP == true)
  {
    if(bIsMultipleOpaqueSupportCTR)
    {
      err = Drm_Reader_DecryptMultipleOpaque(&(m_currentDecryptContext->oDrmDecryptContext),
                                                encryptedRegionIvCounts,
                                                iv_vector,
                                                iv_vector + 1,
                                                &encryptedRegionCounts,
                                                encryptedRegionMapping.size(),
                                                &encryptedRegionMapping[0],
                                                encryptedRegionSkip.size(),
                                                &encryptedRegionSkip[0],
                                                (DRM_DWORD) actualEncDataLength,
                                                (DRM_BYTE *) pEncryptedData,
                                                &decryptedLength,
                                                &pDecryptedContent);
    } else {
      err = Drm_Reader_DecryptOpaque(
                        &(m_currentDecryptContext->oDrmDecryptContext),
                        encryptedRegionMapping.size(),
                        reinterpret_cast<const DRM_DWORD*>(&encryptedRegionMapping[0]),
                        iv_vector[0],
                        actualEncDataLength,
                        (DRM_BYTE *) pEncryptedData,
                        &decryptedLength,
                        &pDecryptedContent);
    }

  }
  else
  {
    bIsAudioNeedNonSVPContext = svpIsAudioNeedNonSVPContext();
    PR_LOG(PR_LOG_TRACE, "bIsAudioNeedNonSVPContext [%u] ",bIsAudioNeedNonSVPContext);

    if(bIsMultipleOpaqueSupportCTR)
    {
      /* For Audio with Non-SVP support*/
      err = Drm_Reader_DecryptMultipleOpaque(&(bIsAudioNeedNonSVPContext ? m_currentDecryptContext->oDrmDecryptAudioContext :
                                                  m_currentDecryptContext->oDrmDecryptContext),
                                                encryptedRegionIvCounts,
                                                iv_vector,
                                                iv_vector + 1,
                                                &encryptedRegionCounts,
                                                encryptedRegionMapping.size(),
                                                &encryptedRegionMapping[0],
                                                encryptedRegionSkip.size(),
                                                &encryptedRegionSkip[0],
                                                (DRM_DWORD) actualEncDataLength,
                                                (DRM_BYTE *) pEncryptedData,
                                                &decryptedLength,
                                                &pDecryptedContent);
    } else {
      err = Drm_Reader_DecryptOpaque(
                        &(bIsAudioNeedNonSVPContext ? m_currentDecryptContext->oDrmDecryptAudioContext :
                                                  m_currentDecryptContext->oDrmDecryptContext),
                        encryptedRegionMapping.size(),
                        reinterpret_cast<const DRM_DWORD*>(&encryptedRegionMapping[0]),
                        iv_vector[0],
                        actualEncDataLength,
                        (DRM_BYTE *) pEncryptedData,
                        &decryptedLength,
                        &pDecryptedContent);
    }

  }

  if (DRM_FAILED(err))
  {
    PR_LOG(PR_LOG_ERROR, "Drm_Reader_DecryptMultipleOpaque failed. 0x%X - %s",err,DRM_ERR_NAME(err));
    DRM_DecryptFailure(err, nullptr, nullptr, nullptr);
#ifdef USE_SVP
    if (useSVP)
    {
      m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
      // Free decrypted secure buffer.
      svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, (void*)m_stSecureBuffInfo.pAVSecBuffer , nullptr, 0);
      svp_buffer_free_token(pSecureToken);
    }
#endif
    return CDMi_S_FALSE;
  }

  if(useSVP)
  {
    // Add a header to the output buffer.
    if (header)
    {
      gst_svp_header_set_field(m_pSVPContext, header, SvpHeaderFieldName::Type, TokenType::Handle);
    }

    memcpy((void *)(uint8_t*)pEncryptedDataStart, pSecureToken, svp_token_size());
    svp_buffer_free_token(pSecureToken);
  }
  else
  {
    if (header)
    {
      gst_svp_header_set_field(m_pSVPContext, header, SvpHeaderFieldName::Type, TokenType::InPlace);
    }

    if(NULL != pDecryptedContent)
    {
        if ((size_t)decryptedLength > actualEncDataLength) {
            free(pDecryptedContent);
            pDecryptedContent = NULL;
            PR_LOG(PR_LOG_ERROR, "decryptedLength[%u] is higher than actualEncDataLength[%u]", decryptedLength, actualEncDataLength);
            return CDMi_S_FALSE;
        }
        memcpy((void *)(uint8_t*)pEncryptedDataStart, pDecryptedContent, decryptedLength);
        free(pDecryptedContent);
        pDecryptedContent = NULL;
        PR_LOG(PR_LOG_TRACE, "InPlace data copy success. decryptedLength[%u", decryptedLength);
    }

  }

  if (useSVP)
  {
    m_stSecureBuffInfo.bReleaseSecureMemRegion = false;
    // Free decrypted secure buffer.
    svp_release_secure_buffers(m_pSVPContext, (void*)&m_stSecureBuffInfo, nullptr , nullptr, 0);
  }

  if (!m_fCommit) {
    err = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, &m_playreadyLevels);
    m_fCommit = TRUE;
  }

  // Copy and Return the Memory token in the incoming payload buffer.
  *outDataLength = inDataLength;
  *outData = inData;

  return CDMi_SUCCESS;

}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ) {
  
  PR_LOG(PR_LOG_DEBUG, "Not implemented");
  return CDMi_SUCCESS;
}

}  // namespace CDMi
