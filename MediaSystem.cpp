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

#include <memory>
#include <vector>
#include <iostream>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <iomanip>
#include <cdmi.h>
#include <core/core.h>

#include <drmint64.h>
#include <unordered_map>

#define CLEAN_ON_INIT 1

/* Default loglevel is set as DEBUG */
uint32_t g_logLevel = PR_LOG_DEBUG;

#define DEVICESTORE_DIGEST_BYTES_SIZE OEM_SHA256_DIGEST_SIZE_IN_BYTES

#define ErrCheckCert() do {                                                \
            if ( m_pbPublisherCert == NULL || m_cbPublisherCert == 0 ) {   \
                fprintf(stderr, "SecureStop publisher certificate is not set."); \
                return CDMi_S_FALSE;                                       \
            }                                                              \
        }while( 0 )

using namespace std;

/* TO DO: temp fix to resolve build error */
#ifndef ENABLE_AMBIGUOUS_FIX
 extern DRM_CONST_STRING g_dstrDrmPath;
#endif

struct KeySystemCtx
{
    DRM_APP_CONTEXT drmAppctx{};
    DRM_BYTE *pbRevocationBuffer{};
    int32_t mediaKeySessionsCount{};
};

WPEFramework::Core::CriticalSection drmAppContextMutex_;

static DRM_WCHAR* createDrmWchar(std::string const& s) {
    DRM_WCHAR* w = new DRM_WCHAR[s.length() + 1];
    for (size_t i = 0; i < s.length(); ++i)
        w[i] = ONE_WCHAR(s[i], '\0');
    w[s.length()] = ONE_WCHAR('\0', '\0');
    return w;
}

static void PackedCharsToNativeImpl(DRM_CHAR *f_pPackedString, DRM_DWORD f_cch) {
    DRM_DWORD ich = 0;
    if( f_pPackedString == nullptr
     || f_cch == 0 )
    {
        return;
    }
    for( ich = 1; ich <= f_cch; ich++ )
    {
        f_pPackedString[f_cch - ich] = ((DRM_BYTE*)f_pPackedString)[ f_cch - ich ];
    }
}

void InitializeLogLevel()
{
    const char* level = getenv("PLAYREADY_RDK_LOG_LEVEL");

    if (level != nullptr)
    {
        int value = atoi(level);
        fprintf(stderr,
            "[PlayReady] Given Log Level = %d\n",value);

        if (value >= PR_LOG_ERROR && value <= PR_LOG_TRACE)
        {
            g_logLevel = static_cast<PRLogLevel>(value);
        }
    }

    fprintf(stderr,
            "[PlayReady] Set Log Level = %d\n",
            g_logLevel);
}

namespace CDMi {

class PlayReady : public IMediaKeys, public IMediaKeysExt {
private:
    class Config : public WPEFramework::Core::JSON::Container {
    private:
        Config& operator= (const Config&);

    public:
        Config () 
            : ReadDir()
            , StoreLocation() {
            Add("read-dir", &ReadDir);
            Add("store-location", &StoreLocation);
            Add("home-path", &HomePath);
        }
        Config (const Config& copy) 
            : ReadDir(copy.ReadDir)
            , StoreLocation(copy.StoreLocation)
            , HomePath(copy.HomePath) {
            Add("read-dir", &ReadDir);
            Add("store-location", &StoreLocation);
            Add("home-path", &HomePath);
        }
        virtual ~Config() {
        }

    public:
        WPEFramework::Core::JSON::String ReadDir;
        WPEFramework::Core::JSON::String StoreLocation;
        WPEFramework::Core::JSON::String HomePath;

        CDMi_RESULT SetSecureStopPublisherCert( const DRM_BYTE*, DRM_DWORD  );
    };

private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

    KeySystemCtx* AcquireKeySystemCtx(const std::string &keySystem) const
    {
        KeySystemCtx *keySystemCtx = nullptr;

        auto it = m_keySystemCtxs.find(keySystem);
        if (it != m_keySystemCtxs.end()) {
            keySystemCtx = it->second.get();
            ++keySystemCtx->mediaKeySessionsCount;
            PR_LOG(PR_LOG_DEBUG, "mediaKeySessionsCount[%d]", keySystemCtx->mediaKeySessionsCount);
        } else {
            std::unique_ptr<KeySystemCtx> ctx(new KeySystemCtx());
            CDMi_RESULT cResult = InitializeAppCtx(getStoreLocation(keySystem), *ctx);

            if (cResult == CDMi_SUCCESS) {
                ctx->mediaKeySessionsCount = 1;
                keySystemCtx = ctx.get();
                m_keySystemCtxs.emplace(keySystem, std::move(ctx));
            } else {
                PR_LOG(PR_LOG_ERROR, "InitializeAppCtx failed for keySystem[%s]. 0x%X", keySystem.c_str(), cResult);
            }
        }

        return keySystemCtx;
    }

    void ReleaseKeySystemCtx(const std::string &keySystem) const
    {		
        auto keySystemCtx = m_keySystemCtxs.find(keySystem);
        if (keySystemCtx == m_keySystemCtxs.end()) {
            PR_LOG(PR_LOG_WARN, "No context found for keySystem[%s]", keySystem.c_str());
            return;
        }

        if (keySystemCtx->second->mediaKeySessionsCount > 0) {
            --keySystemCtx->second->mediaKeySessionsCount;
        }

        PR_LOG(PR_LOG_DEBUG, "mediaKeySessionsCount[%d]", keySystemCtx->second->mediaKeySessionsCount);
        
        if (keySystemCtx->second->mediaKeySessionsCount == 0) {
            UninitializeAppCtx(*keySystemCtx->second);
            m_keySystemCtxs.erase(keySystemCtx);
        }
    }

    void CleanLicenseStore()
    {
        std::vector<std::string> storeFilePaths;
        DIR *dir = opendir(m_readDir.c_str());
        if (dir) {
            struct dirent *dir_entry{};
            while ((dir_entry = readdir(dir)) != NULL) {
                if (strcmp(dir_entry->d_name, ".") && strcmp(dir_entry->d_name, "..")) {
                    std::string filePath = m_readDir;
                    if (filePath.back() != '/') {
                        filePath += '/';
                    }
                    filePath += dir_entry->d_name;
                    storeFilePaths.push_back(std::move(filePath));
                }
            }
            closedir(dir);
        }

        for (const auto &storeFilePath : storeFilePaths) {
            KeySystemCtx storeCtx;
            CDMi_RESULT cResult = InitializeAppCtx(storeFilePath, storeCtx);
            if (cResult == CDMi_SUCCESS) {
                DRM_RESULT dr = Drm_StoreMgmt_CleanupStore(&storeCtx.drmAppctx,
                                         DRM_STORE_CLEANUP_DELETE_EXPIRED_LICENSES |
                                         DRM_STORE_CLEANUP_DELETE_REMOVAL_DATE_LICENSES,
                                         nullptr, 0, nullptr);
                PR_LOG(PR_LOG_DEBUG, "Cleanup result for store '%s'. 0x%X", storeFilePath.c_str(), dr);
                UninitializeAppCtx(storeCtx);
            } 
            else {
                PR_LOG(PR_LOG_WARN, "InitializeAppCtx failed for store '%s'", storeFilePath.c_str());
            }
        }
    }

    const std::string getStoreLocation(const std::string &keySystem) const
    {
        return m_storeLocation + "_" + keySystem;
    }

public:

    PlayReady() {
    }

    ~PlayReady(void) {
        SAFE_OEM_FREE( m_pbPublisherCert );
    }

    CDMi_RESULT UpdateDrmClock(DRM_APP_CONTEXT *appContext) const
    {
        DRMFILETIME               ftSystemTime; /* Initialized by Drm_SecureTime_GetValue */
        DRM_SECURETIME_CLOCK_TYPE eClockType;   /* Initialized by Drm_SecureTime_GetValue */
        DRM_RESULT dr = DRM_SUCCESS;
        CDMi_RESULT cResult = CDMi_SUCCESS;
        bool bIsInitSecureClockNeed = false;

        PR_LOG(PR_LOG_DEBUG, "entry");

        for(;;) {
            bIsInitSecureClockNeed = svpIsSecureClockInitNeed();

            PR_LOG(PR_LOG_DEBUG, "bIsInitSecureClockNeed [%d]", bIsInitSecureClockNeed);

            if(!bIsInitSecureClockNeed) {
                cResult = CDMi_SUCCESS;
                break;
            }

            PR_LOG(PR_LOG_DEBUG, "Drm_SecureTime_GetValue calling...");
            dr = Drm_SecureTime_GetValue(appContext, &ftSystemTime, &eClockType);
            if (dr == DRM_E_CLK_NOT_SUPPORTED)  /* Secure Clock not supported, try the Anti-Rollback Clock */
            {
                PR_LOG(PR_LOG_WARN, "Drm_SecureTime_GetValue return 0x%X - %s",dr,DRM_ERR_NAME(dr));
#if defined DRM_ANTI_ROLLBACK_CLOCK_SUPPORT
                DRMSYSTEMTIME   systemTime;
                struct timeval  tv;
                struct tm      *tm;

                PR_LOG(PR_LOG_DEBUG, "Secure Clock not supported, trying the Anti-Rollback Clock...");

                gettimeofday(&tv, nullptr);
                tm = gmtime(&tv.tv_sec);

                systemTime.wYear         = tm->tm_year+1900;
                systemTime.wMonth        = tm->tm_mon+1;
                systemTime.wDayOfWeek    = tm->tm_wday;
                systemTime.wDay          = tm->tm_mday;
                systemTime.wHour         = tm->tm_hour;
                systemTime.wMinute       = tm->tm_min;
                systemTime.wSecond       = tm->tm_sec;
                systemTime.wMilliseconds = tv.tv_usec/1000;

                dr = Drm_AntiRollBackClock_Init(appContext, &systemTime);
                if( dr != 0)
                {
                    PR_LOG(PR_LOG_ERROR, "Failed to initialize Anti-Rollback Clock, quitting....0x%X - %s",dr,DRM_ERR_NAME(dr));
                    cResult = CDMi_FAIL;
                    break;
                }

                break;
#else
            PR_LOG(PR_LOG_ERROR, "Secure Clock and Anti-Rollback Clock is not supported...");
            cResult = CDMi_FAIL;
            break;
#endif
            }

            PR_LOG(PR_LOG_DEBUG, "Drm_SecureTime_GetValue return 0x%X - %s",dr,DRM_ERR_NAME(dr));
            if (dr != 0) {
                PR_LOG(PR_LOG_ERROR, "Expect platform to support Secure Clock or Anti-Rollback Clock.");
                cResult = CDMi_FAIL;
                break;
            }

            break;
        }

        return cResult;
    }

    CDMi_RESULT CreateMediaKeySession(
        const std::string & keySystem,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {
        DRM_RESULT rnd = DRM_S_FALSE;
        PR_LOG(PR_LOG_DEBUG, "entry");

        SafeCriticalSection systemLock(drmAppContextMutex_);

        auto keySystemCtx = AcquireKeySystemCtx(keySystem);
        if (keySystemCtx == nullptr) {
            PR_LOG(PR_LOG_ERROR, "No valid context available for keySystem[%s]", keySystem.c_str());
            return CDMi_FAIL;
        }

        /* Update the DRM Secure Clock time */
        if (CDMi_SUCCESS != UpdateDrmClock(&keySystemCtx->drmAppctx)) {
            PR_LOG(PR_LOG_ERROR, "Drm Clock update failed");
            ReleaseKeySystemCtx(keySystem);
            return CDMi_FAIL;
        }

        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, f_pbCDMData, f_cbCDMData, &keySystemCtx->drmAppctx, keySystem);

        /* Store the MediaKeySession with random generated SessionId */
        do {
            rnd = Oem_Random_GetBytes(nullptr, reinterpret_cast<DRM_BYTE*>(&m_sessionId), SIZEOF(m_sessionId));
        } while (rnd == DRM_SUCCESS && (m_sessionMap.find(m_sessionId) != m_sessionMap.end()));

        if (DRM_FAILED(rnd)) {
            PR_LOG(PR_LOG_ERROR, "Failed to generate sessionId");
            delete *f_ppiMediaKeySession;
            *f_ppiMediaKeySession = nullptr;
            ReleaseKeySystemCtx(keySystem);
            return CDMi_FAIL;
        }
        m_sessionMap.emplace(m_sessionId, *f_ppiMediaKeySession);

        /* Session count */
        ++m_sessionCount;

        PR_LOG(PR_LOG_DEBUG, "exit MediakeySession[%p] m_sessionId[%u] sessionCount[%u]", static_cast<void*>(*f_ppiMediaKeySession), m_sessionId, m_sessionCount);
        return CDMi_SUCCESS;
    }

    CDMi_RESULT SetSecureStopPublisherCert( const DRM_BYTE *f_pbPublisherCert, DRM_DWORD f_cbPublisherCert )
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        if ( NULL == f_pbPublisherCert )
        {
            PR_LOG(PR_LOG_ERROR, "f_pbPublisherCert is null");
            return CDMi_FAIL;
        }
        if ( 0 == f_cbPublisherCert )
        {
            PR_LOG(PR_LOG_ERROR, "f_cbPublisherCert is zero");
            return CDMi_FAIL;
        }

        SAFE_OEM_FREE( m_pbPublisherCert );
        m_cbPublisherCert = 0;

        m_pbPublisherCert = (DRM_BYTE *)Oem_MemAlloc( f_cbPublisherCert );
        ZEROMEM( m_pbPublisherCert, f_cbPublisherCert );
        memcpy( m_pbPublisherCert, f_pbPublisherCert, f_cbPublisherCert );

        m_cbPublisherCert = f_cbPublisherCert;
        PR_LOG(PR_LOG_DEBUG, "exit");
        return CDMi_SUCCESS;
    }

    CDMi_RESULT SetServerCertificate( const uint8_t *f_pbServerCertificate, uint32_t f_cbServerCertificate)
    {
        PR_LOG(PR_LOG_DEBUG, "entry");

        CDMi_RESULT cr = CDMi_SUCCESS;
        if ( CDMi_FAILED( ( cr=SetSecureStopPublisherCert( f_pbServerCertificate, f_cbServerCertificate ) ) ) )
        {
            PR_LOG(PR_LOG_ERROR, "SetSecureStopPublisherCert failed");
        }

        PR_LOG(PR_LOG_DEBUG, "exit result:0x%X", cr);
        return cr;
    }

    virtual CDMi_RESULT Metrics(uint32_t length, const uint8_t* buffer)
    {
       PR_LOG(PR_LOG_DEBUG, "Not implemented");
       return CDMi_SUCCESS;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {

        CDMi_RESULT cResult = CDMi_S_FALSE;
        bool sessionFound = false;

        PR_LOG(PR_LOG_DEBUG, "entry m_sessionCount[%d]", m_sessionCount);

        SafeCriticalSection systemLock(drmAppContextMutex_);

        for(;;) {
            if(f_piMediaKeySession == NULL) {
                PR_LOG(PR_LOG_ERROR, "Invalid input, f_piMediaKeySession is null");
                cResult = CDMi_INVALID_ARG;
                break;
            }

            if(m_sessionCount == 0) {
                PR_LOG(PR_LOG_ERROR, "Session is missing in sessionMap");
                cResult = CDMi_FAIL;
                break;
            }

            /* Ensure the given session is valid
            * Check the session from the sessionMap
            */
            for (auto& entry : m_sessionMap)
            {
                uint32_t sessionId = entry.first;
                IMediaKeySession* session = entry.second;

                if (session == f_piMediaKeySession)
                {
                    sessionFound = true;
                    PR_LOG(PR_LOG_DEBUG, "Found the session[%p] Id[%u] from sessionMap", f_piMediaKeySession, sessionId);
                    const std::string keySystem = session->GetKeySystem();
                    delete session;
                    ReleaseKeySystemCtx(keySystem);
                    /* remove the sessionId mapping from the sessionMap list */
                    m_sessionMap.erase(sessionId);

                    /* decrease the session count */
                    --m_sessionCount;
                    cResult = CDMi_SUCCESS;
                    break;
                }
            }

            if(!sessionFound) {
                PR_LOG(PR_LOG_ERROR, "session[%p] not found in sessionMap", f_piMediaKeySession);
                cResult = CDMi_FAIL;
                break;
            }

            break;
        }

        PR_LOG(PR_LOG_DEBUG, "exit result[0x%X]", cResult);
        return cResult;
    }
    
    uint64_t GetDrmSystemTime(const std::string &keySystem) const /* override */
    {
        DRM_RESULT dr                        = DRM_SUCCESS;
        DRM_SECURETIME_CLOCK_TYPE eClockType = DRM_SECURETIME_CLOCK_TYPE_INVALID;
        DRMFILETIME oftSystemTime            = { 0 };
        uint64_t ui64RetTime                 = (uint64_t) -1;

        PR_LOG(PR_LOG_DEBUG, "entry keySystem[%s]", keySystem.c_str());

        SafeCriticalSection lock(drmAppContextMutex_);
        
        auto keySystemCtx = AcquireKeySystemCtx(keySystem);
        if (keySystemCtx == nullptr) {
            PR_LOG(PR_LOG_ERROR, "No valid context available for keySystem[%s]", keySystem.c_str());
            return ui64RetTime;
        }

        dr = Drm_SecureTime_GetValue(&keySystemCtx->drmAppctx, &oftSystemTime, &eClockType);

        ReleaseKeySystemCtx(keySystem);

        if ( dr != DRM_SUCCESS )
        {
            PR_LOG(PR_LOG_ERROR, "Drm_SecureTime_GetValue failed. 0x%X - %s",dr,DRM_ERR_NAME(dr));
        }
        else if ( eClockType == DRM_SECURETIME_CLOCK_TYPE_INVALID )
        {
            PR_LOG(PR_LOG_ERROR, "Drm_SecureTime_GetValue returned an invalid clock type");
        }
        else
        {
            DRM_UINT64 ui64 = DRM_UI64LITERAL(0, 0);

            FILETIME_TO_UI64( oftSystemTime, ui64 );
            ui64RetTime = ( uint64_t ) DRM_UI2I64( ui64 );
        }
        PR_LOG(PR_LOG_DEBUG, "exit");
        return ui64RetTime;
    }

    CDMi_RESULT CreateMediaKeySessionExt(
            const std::string& keySystem,
            const uint8_t drmHeader[],
            uint32_t drmHeaderLength,
            IMediaKeySessionExt** session) /* override */
    {
        DRM_RESULT rnd = DRM_S_FALSE;
        PR_LOG(PR_LOG_DEBUG, "entry m_sessionCount[%d]", m_sessionCount);

        SafeCriticalSection systemLock(drmAppContextMutex_);

        if(session == NULL) {
            PR_LOG(PR_LOG_DEBUG, "Invalid input, session is null");
            return CDMi_INVALID_ARG;
        }

        auto keySystemCtx = AcquireKeySystemCtx(keySystem);
        if (keySystemCtx == nullptr) {
            PR_LOG(PR_LOG_ERROR, "No valid context available for keySystem[%s]", keySystem.c_str());
            return CDMi_FAIL;
        }

        *session = new CDMi::MediaKeySession(drmHeader, drmHeaderLength, nullptr, 0, &keySystemCtx->drmAppctx, keySystem);

        /* Store the MediaKeySession with random generated SessionId */
        do {
            rnd = Oem_Random_GetBytes(nullptr, reinterpret_cast<DRM_BYTE*>(&m_sessionId), SIZEOF(m_sessionId));
        } while (rnd == DRM_SUCCESS && (m_sessionMap.find(m_sessionId) != m_sessionMap.end()));

        if (DRM_FAILED(rnd)) {
            PR_LOG(PR_LOG_ERROR, "Failed to generate sessionId");
            delete *session;
            *session = nullptr;
            ReleaseKeySystemCtx(keySystem);
            return CDMi_FAIL;
        }
        m_sessionMap.emplace(m_sessionId, reinterpret_cast<IMediaKeySession*>(*session));

        /* Session count */
        ++m_sessionCount;

        PR_LOG(PR_LOG_DEBUG, "exit MediakeySession[%p] m_sessionId[%u] sessionCount[%u]",reinterpret_cast<void*>(*session), m_sessionId, m_sessionCount);

        return CDMi_SUCCESS;
    }

    CDMi_RESULT DestroyMediaKeySessionExt(IMediaKeySession *f_piMediaKeySession)
    {
        CDMi_RESULT cResult = CDMi_S_FALSE;
        bool sessionFound = false;

        SafeCriticalSection systemLock(drmAppContextMutex_);

        PR_LOG(PR_LOG_DEBUG, "entry m_sessionCount[%d]", m_sessionCount);

        for(;;) {
            if(f_piMediaKeySession == NULL) {
                PR_LOG(PR_LOG_ERROR, "Invalid input, f_piMediaKeySession is null");
                cResult = CDMi_INVALID_ARG;
                break;
            }

            if(m_sessionCount == 0) {
                PR_LOG(PR_LOG_ERROR, "Session is missing in sessionMap");
                cResult = CDMi_FAIL;
                break;
            }

            /* Ensure the given session is valid
            * Check the session from the sessionMap
            */
            for (auto& entry : m_sessionMap)
            {
                uint32_t sessionId = entry.first;
                IMediaKeySession* session = entry.second;

                if (session == f_piMediaKeySession)
                {
                    sessionFound = true;
                    PR_LOG(PR_LOG_DEBUG, "Found the session[0x%X] Id[%u] from sessionMap", f_piMediaKeySession, sessionId);
                    const std::string keySystem = session->GetKeySystem();
                    delete session;
                    ReleaseKeySystemCtx(keySystem);
                    /* remove the sessionId mapping from the sessionMap list */
                    m_sessionMap.erase(sessionId);

                    /* decrease the session count */
                    --m_sessionCount;
                    cResult = CDMi_SUCCESS;
                    break;
                }
            }

            if(!sessionFound) {
                PR_LOG(PR_LOG_ERROR, "session[0x%X] not found in sessionMap", f_piMediaKeySession);
                cResult = CDMi_FAIL;
                break;
            }

            break;
        }

        PR_LOG(PR_LOG_DEBUG, "exit result[0x%X]", cResult);

        return cResult;
    }

    std::string GetVersionExt() const /* override */
    {
        const uint32_t MAXLEN = 64;
        char versionStr[MAXLEN];
        PR_LOG(PR_LOG_DEBUG, "entry");
#if defined PLAYREADY_VERSION_4_6
        if (g_dstrReqTagPKClientVersionData.cchString >= MAXLEN)
            return "";
        DRM_UTL_DemoteUNICODEtoASCII(g_dstrReqTagPKClientVersionData.pwszString,
                versionStr, MAXLEN);
        ((DRM_BYTE*)versionStr)[g_dstrReqTagPKClientVersionData.cchString] = 0;
        PackedCharsToNativeImpl(versionStr, g_dstrReqTagPKClientVersionData.cchString + 1);
        for(int index = 0; index < g_dstrReqTagPKClientVersionData.cchString; ++index) {
            PR_LOG(PR_LOG_TRACE, "[%c]", versionStr[index]);
        }
        PR_LOG(PR_LOG_TRACE, "\n");
#else
        if (g_dstrReqTagPlayReadyClientVersionData.cchString >= MAXLEN)
            return "";
        DRM_UTL_DemoteUNICODEtoASCII(g_dstrReqTagPlayReadyClientVersionData.pwszString,
                versionStr, MAXLEN);
        ((DRM_BYTE*)versionStr)[g_dstrReqTagPlayReadyClientVersionData.cchString] = 0;
        PackedCharsToNativeImpl(versionStr, g_dstrReqTagPlayReadyClientVersionData.cchString + 1);

        for(int index = 0; index < g_dstrReqTagPlayReadyClientVersionData.cchString; ++index) {
            PR_LOG(PR_LOG_TRACE, "[%c]", versionStr[index]);
        }
        PR_LOG(PR_LOG_TRACE, "\n");
#endif /* PLAYREADY_VERSION_4_6 */
        return string(versionStr);
    }

    uint32_t GetLdlSessionLimit() const /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "LdlSessionLimit [%u]",(uint32_t)DRM_MAX_NONCE_COUNT_PER_SESSION);
        return ( uint32_t )DRM_MAX_NONCE_COUNT_PER_SESSION;
    }

    bool IsSecureStopEnabled() /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "true");
        return true;
    }

    CDMi_RESULT EnableSecureStop(bool enable) /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "Not implemented");
        return CDMi_SUCCESS;
    }

    uint32_t ResetSecureStops() /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "Not implemented");
        return 0;
    }

    /*Return a list of the current SecureStop sessions.*/
    CDMi_RESULT GetSecureStopIds(const std::string &keySystem, uint8_t ids[], uint16_t idsLength, uint32_t & count)
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        SafeCriticalSection lock(drmAppContextMutex_);

        CDMi_RESULT cr           = CDMi_SUCCESS;
        DRM_ID     *pidSessions  = NULL;
        DRM_DWORD   cidSessions  = 0;
        DRM_DWORD   cBytesNeeded = 0;

        ErrCheckCert();

        auto keySystemCtx = AcquireKeySystemCtx(keySystem);
        if (keySystemCtx == nullptr) {
            PR_LOG(PR_LOG_ERROR, "No valid context available for keySystem[%s]", keySystem.c_str());
            return CDMi_S_FALSE;
        }

        DRM_RESULT err = Drm_SecureStop_EnumerateSessions(
                &keySystemCtx->drmAppctx,
                m_cbPublisherCert,
                m_pbPublisherCert,
                &cidSessions,
                &pidSessions );
        
        ReleaseKeySystemCtx(keySystem);

        if ( err == DRM_SUCCESS )
        {
            cBytesNeeded = cidSessions * DRM_ID_SIZE;
            if ( idsLength < cBytesNeeded )
            {
                count = cidSessions;
                cr = CDMi_S_FALSE;
            }
            else
            {
                count = cidSessions;

                for ( DRM_DWORD i = 0; i < count; ++i)
                {
                    memcpy(&ids[i * DRM_ID_SIZE], pidSessions[i].rgb, DRM_ID_SIZE);
                }
            }
        }
        else
        {
            PR_LOG(PR_LOG_ERROR, "Drm_GetSecureStopIds failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            cr = CDMi_S_FALSE;
        }

        SAFE_OEM_FREE( pidSessions );
        PR_LOG(PR_LOG_DEBUG, "exit");
        return cr;
    }

    /*Generate a SecureStop challenge to send to the server.*/
    CDMi_RESULT GetSecureStop(
            const std::string &keySystem,
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            uint8_t * f_pbChallenge,
            uint16_t & f_cbChallenge)
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        SafeCriticalSection lock(drmAppContextMutex_);

        if ( sessionIDLength < DRM_ID_SIZE )
        {
            PR_LOG(PR_LOG_ERROR, "Invalid argument: sessionIDlength %zu expecting %zu",sessionIDLength,DRM_ID_SIZE);
            return CDMi_INVALID_ARG;
        }

        if (f_cbChallenge == 0 || f_pbChallenge == nullptr )
        {
            PR_LOG(PR_LOG_ERROR, "Invalid argument: f_cbChallenge[%u] f_pbChallenge[%p]",
                                                                static_cast<unsigned>(f_cbChallenge),
                                                                static_cast<void*>(f_pbChallenge));
            return CDMi_INVALID_ARG;
        }

        ErrCheckCert();

        auto keySystemCtx = AcquireKeySystemCtx(keySystem);
        if (keySystemCtx == nullptr) {
            PR_LOG(PR_LOG_ERROR, "No valid context available for keySystem[%s]", keySystem.c_str());
            return CDMi_S_FALSE;
        }

        DRM_BYTE   *pbChallenge = NULL;
        DRM_DWORD   cbChallenge = 0;
        DRM_ID      SID         = DRM_ID_EMPTY;
        CDMi_RESULT cr          = CDMi_SUCCESS;

        ::memcpy( (void*)SID.rgb, (const void*)&sessionID[0], DRM_ID_SIZE );

        DRM_RESULT err = Drm_SecureStop_GenerateChallenge(
                &keySystemCtx->drmAppctx,
                &SID,
                m_cbPublisherCert,
                m_pbPublisherCert,
                0,
                nullptr,
                &cbChallenge,
                &pbChallenge );

        ReleaseKeySystemCtx(keySystem);

        if ( err != DRM_SUCCESS )
        {
            f_cbChallenge = 0;
            PR_LOG(PR_LOG_ERROR, "Drm_SecureStop_GenerateChallenge failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            cr = CDMi_S_FALSE;
        }
        else if ( f_cbChallenge < cbChallenge )
        {
            f_cbChallenge = (uint16_t)cbChallenge;
            PR_LOG(PR_LOG_ERROR, "SecureStop challenge buffer is too small. %u, need %u",f_cbChallenge,cbChallenge);
            cr = CDMi_S_FALSE;
        }
        else
        {
            f_cbChallenge = (uint16_t)cbChallenge;
            ::memcpy( f_pbChallenge, pbChallenge, f_cbChallenge );
        }

        SAFE_OEM_FREE( pbChallenge );
        PR_LOG(PR_LOG_DEBUG, "exit");
        return cr;
    }

    /*Process the response from the SecureStop server.*/
    CDMi_RESULT CommitSecureStop(
            const std::string &keySystem,
            const uint8_t f_sessionID[],
            uint32_t f_sessionIDLength,
            const uint8_t f_serverResponse[],
            uint32_t f_serverResponseLength) /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        SafeCriticalSection lock(drmAppContextMutex_);

        ErrCheckCert();

        if ( f_sessionIDLength < DRM_ID_SIZE )
        {
            PR_LOG(PR_LOG_ERROR, "Invalid argument: sessionIDlength %zu, expecting %zu ",f_sessionIDLength,DRM_ID_SIZE);
            return CDMi_INVALID_ARG;
        }

        auto keySystemCtx = AcquireKeySystemCtx(keySystem);
        if (keySystemCtx == nullptr) {
            PR_LOG(PR_LOG_ERROR, "No valid context available for keySystem[%s]", keySystem.c_str());
            return CDMi_S_FALSE;
        }

        DRM_ID      SID             = DRM_ID_EMPTY;
        DRM_CHAR   *pcchCustomData  = NULL;
        DRM_DWORD   cchCustomData   = 0;
        CDMi_RESULT cr              = CDMi_SUCCESS;

        memcpy( (void*)SID.rgb, (const void*)&f_sessionID[0], DRM_ID_SIZE );

        DRM_RESULT err = Drm_SecureStop_ProcessResponse(
                &keySystemCtx->drmAppctx,
                &SID,
                m_cbPublisherCert,
                m_pbPublisherCert,
                f_serverResponseLength,
                f_serverResponse,
                &cchCustomData,
                &pcchCustomData);

        ReleaseKeySystemCtx(keySystem);

        if ( err == DRM_E_SECURESTOP_SESSION_NOT_FOUND )
        {
            cr = CDMi_S_FALSE;
        }
        else if (err != DRM_SUCCESS)
        {
            PR_LOG(PR_LOG_ERROR, " Drm_SecureStop_ProcessResponse failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            cr = CDMi_S_FALSE;
        }
        SAFE_OEM_FREE( pcchCustomData ); 
        PR_LOG(PR_LOG_DEBUG, "exit");
        return cr;
    }

    CDMi_RESULT CreateSystemExt() /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "entry");

        std::string rdir(m_readDir);

        drmdir_ = createDrmWchar(rdir);

        g_dstrDrmPath.pwszString = drmdir_;
        g_dstrDrmPath.cchString = rdir.length();

        // Store store location
        std::string store(m_storeLocation);

        PR_LOG(PR_LOG_DEBUG, "m_storeLocation[%s]", store.c_str());

        PR_LOG(PR_LOG_DEBUG, "exit");
        return CDMi_SUCCESS;
    }

    /*Initialize the PlayReady application context*/
    CDMi_RESULT InitializeAppCtx(const std::string &storeLocation, KeySystemCtx &keySystemCtx) const
    {
        DRM_BYTE *appOpaqueBuffer = nullptr;
        DRM_VOID *pDrmOemContext = NULL;
        bool bIsInitSecureClockNeed = false;
        bool isAppCtxInitialized = false;
        CDMi_RESULT cResult = CDMi_S_FALSE;
        DRM_CONST_STRING dstrHDSPath = DRM_EMPTY_DRM_STRING;

        dstrHDSPath.pwszString =  createDrmWchar(storeLocation);
        dstrHDSPath.cchString = storeLocation.length();

        PR_LOG(PR_LOG_DEBUG, "entry m_sessionCount[%d]", m_sessionCount);

        for(;;) {

            PR_LOG(PR_LOG_TRACE, "OpaqueBuffer Size[%u]", MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE);
            // Init opaque buffer.
            appOpaqueBuffer = new DRM_BYTE[MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE];

            svpGetDrmOEMContext(&pDrmOemContext);

            PR_LOG(PR_LOG_DEBUG, "call Drm_Initialize");

            DRM_RESULT err  = Drm_Initialize(&keySystemCtx.drmAppctx, pDrmOemContext,
                                appOpaqueBuffer,
                                MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                                &dstrHDSPath);

            if((err == DRM_E_SECURESTOP_STORE_CORRUPT) || \
                    (err == DRM_E_SECURESTORE_CORRUPT) || \
                    (err == DRM_E_DST_CORRUPTED)) {

                PR_LOG(PR_LOG_WARN, "Drm_Initialize failed. 0x%X - %s",err,DRM_ERR_NAME(err));
                PR_LOG(PR_LOG_WARN, "Remove store path and try again");
                //if drmstore file is corrupted, remove it and init again, playready will create a new one
                remove(storeLocation.c_str());
                err = Drm_Initialize(&keySystemCtx.drmAppctx, pDrmOemContext,
                                    appOpaqueBuffer,
                                    MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                                    &dstrHDSPath );
            }

            if (DRM_FAILED(err)) {
                PR_LOG(PR_LOG_ERROR, "Drm_Initialize failed. 0x%X - %s",err,DRM_ERR_NAME(err));
                cResult = CDMi_FAIL;
                break;
            }

            isAppCtxInitialized = true;
            cResult = CDMi_SUCCESS;
            PR_LOG(PR_LOG_DEBUG, "Drm_Initialize success");

            keySystemCtx.pbRevocationBuffer = new DRM_BYTE[REVOCATION_BUFFER_SIZE];
            ::memset(keySystemCtx.pbRevocationBuffer, 0, REVOCATION_BUFFER_SIZE);
            err = Drm_Revocation_SetBuffer(&keySystemCtx.drmAppctx, keySystemCtx.pbRevocationBuffer, REVOCATION_BUFFER_SIZE);
            if(DRM_FAILED(err)) {
                PR_LOG(PR_LOG_ERROR, "Drm_Revocation_SetBuffer failed. 0x%X - %s",err,DRM_ERR_NAME(err));
                cResult = CDMi_FAIL;
                break;
            }

            /* Update the DRM Secure Clock time */
            cResult = UpdateDrmClock(&keySystemCtx.drmAppctx);
            if (CDMi_SUCCESS != cResult) {
                PR_LOG(PR_LOG_ERROR, "Drm Clock update failed");
                cResult = CDMi_FAIL;
                break;
            }

            if( !svpLoadRevocationList())
            {
                PR_LOG(PR_LOG_ERROR, "Failed to load revocation list");
                cResult = CDMi_FAIL;
                break;
            }

            break;
        }

        if(CDMi_SUCCESS != cResult) {
            if(isAppCtxInitialized) {
                Drm_Uninitialize(&keySystemCtx.drmAppctx);
            }

            delete [] appOpaqueBuffer;
            delete [] keySystemCtx.pbRevocationBuffer;
            keySystemCtx.pbRevocationBuffer = nullptr;
        }

        delete [] dstrHDSPath.pwszString;

        PR_LOG(PR_LOG_DEBUG, "exit cResult[0x%X]", cResult);
        return cResult;
    }

    /*Unitialize the playready context and opaque buffer*/
    CDMi_RESULT UninitializeAppCtx(KeySystemCtx &keySystemCtx) const
    {
        DRM_BYTE *pbOldBuf = nullptr;
        DRM_DWORD cbOldBuf = 0;
        CDMi_RESULT cResult = CDMi_S_FALSE;

        PR_LOG(PR_LOG_DEBUG, "entry sessionCount[%d]", m_sessionCount);

        for(;;) {
            DRM_RESULT err = Drm_GetOpaqueBuffer( &keySystemCtx.drmAppctx, &pbOldBuf, &cbOldBuf );
            if(DRM_FAILED(err))
            {
                PR_LOG(PR_LOG_WARN, "Drm_GetOpaqueBuffer failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            }

            Drm_Uninitialize(&keySystemCtx.drmAppctx);

            if ( pbOldBuf ){
                PR_LOG(PR_LOG_TRACE, "opaquebuffer freed");
                delete [] pbOldBuf;
            }

            delete [] keySystemCtx.pbRevocationBuffer;
            keySystemCtx.pbRevocationBuffer = nullptr;

            cResult = CDMi_SUCCESS;

            break;
        }

        PR_LOG(PR_LOG_DEBUG, "exit");
        return cResult;
    }

    CDMi_RESULT InitSystemExt() /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        CDMi_RESULT cResult = CDMi_S_FALSE;
        DRM_RESULT err = DRM_S_FALSE;

        SafeCriticalSection lock(drmAppContextMutex_);

        for(;;) {
            err = CPRDrmPlatform::DrmPlatformInitialize();

            if(DRM_FAILED(err))
            {
                PR_LOG(PR_LOG_ERROR, "DrmPlatformInitialize failed 0x%X - %s",err,DRM_ERR_NAME(err));
                cResult = CDMi_FAIL;
                break;
            }

            CleanLicenseStore();
            cResult = CDMi_SUCCESS;
            break;
        }

        PR_LOG(PR_LOG_DEBUG, "exit");
        return cResult;
    }

    void Deinitialize(const WPEFramework::PluginHost::IShell * shell)
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        CDMi_RESULT cr = TeardownSystemExt();
        if (CDMi_SUCCESS != cr)
        {
            PR_LOG(PR_LOG_ERROR, "TeardownSystemExt failed. 0x%X;  skipping platform uninit",cr);
            return;
        }
        /* We can do SoC specific de-init requirement for Playready */
        svpPlatformUninitializePlayready();
        PR_LOG(PR_LOG_DEBUG, "exit");
    }

    CDMi_RESULT TeardownSystemExt() /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        SafeCriticalSection systemLock(drmAppContextMutex_);
        
        PR_LOG(PR_LOG_INFO, "m_sessionCount[%d]", m_sessionCount);
        /* Clean all the MediaKeysessions */
        for (auto& entry : m_sessionMap)
        {
            uint32_t sessionId = entry.first;
            IMediaKeySession* session = entry.second;

            if (session != nullptr)
            {
                PR_LOG(PR_LOG_INFO, "Close the session sessionId[%d]", sessionId);
                const std::string keySystem = session->GetKeySystem();
                delete session;
                ReleaseKeySystemCtx(keySystem);
            }
        }

        m_sessionMap.clear();
        m_sessionCount = 0;
        if (!m_keySystemCtxs.empty()) {
            PR_LOG(PR_LOG_ERROR, "Key system contexts not released properly");
        }

        delete [] drmdir_;

        CleanLicenseStore();

        DRM_RESULT err = CPRDrmPlatform::DrmPlatformUninitialize();
        if(DRM_FAILED(err))
        {
            PR_LOG(PR_LOG_DEBUG, "DrmPlatformUninitialize failed. 0x%X - %s",err,DRM_ERR_NAME(err));
            return CDMi_S_FALSE;
        }

        PR_LOG(PR_LOG_DEBUG, "DrmPlatformUninitialize success");
        return CDMi_SUCCESS;
    }

    CDMi_RESULT DeleteKeyStore() /* override */
    {
        PR_LOG(PR_LOG_DEBUG, "Not implemented");
        return CDMi_S_FALSE;
    }

    CDMi_RESULT DeleteSecureStore(const std::string &keySystem) /* override */
    {
        CDMi_RESULT cr = CDMi_SUCCESS;
        DRM_RESULT  dr = DRM_SUCCESS;
        struct stat buf;

        PR_LOG(PR_LOG_DEBUG, "entry keySystem[%s]", keySystem.c_str());
        SafeCriticalSection systemLock(drmAppContextMutex_);

        const std::string storeLocation = getStoreLocation(keySystem);
        cr = CDMi_SUCCESS;
        if (stat(storeLocation.c_str(), &buf) != -1)
        {
            int status = remove(storeLocation.c_str());
            if(status == 0)
            {
                cr = CDMi_SUCCESS;
            }
            else
            {
                PR_LOG(PR_LOG_ERROR, "Failed to delete key store");
                cr = CDMi_S_FALSE;
            }
        }
        else
            cr = CDMi_SUCCESS;

        PR_LOG(PR_LOG_DEBUG, "exit cr[0x%X]", cr);
        return cr;
    }

    CDMi_RESULT GetKeyStoreHash(
            uint8_t keyStoreHash[],
            uint32_t keyStoreHashLength) // override
    {
        PR_LOG(PR_LOG_DEBUG, "Not implemented");
        return CDMi_S_FALSE;
    }

    CDMi_RESULT GetSecureStoreHash(
            const std::string &keySystem,
            uint8_t secureStoreHash[],
            uint32_t secureStoreHashLength) // override
    {
        PR_LOG(PR_LOG_DEBUG, "entry");
        SafeCriticalSection lock(drmAppContextMutex_);
        CDMi_RESULT ret = CDMi_SUCCESS;

        const std::string storeLocation = getStoreLocation(keySystem);
        FILE* const file = fopen(storeLocation.c_str(), "rb");
        if (!file) {
            PR_LOG(PR_LOG_ERROR, "exit. file open failed [%s]", storeLocation.c_str());
             return CDMi_S_FALSE;
        }

        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const int BUFSIZE = 32768;
        std::vector<unsigned char> buffer(BUFSIZE, 0);
        size_t bytesRead = 0;
        while ((bytesRead = fread(&buffer[0], 1, BUFSIZE, file))) {
            if (!SHA256_Update(&sha256, &buffer[0], bytesRead)) {
                ret = CDMi_S_FALSE;
                break;
            }
        }
        fclose(file);
        SHA256_Final(secureStoreHash, &sha256);
        PR_LOG(PR_LOG_DEBUG, "exit");
        return ret;
    }

    void OnSystemConfigurationAvailable(const std::string& configline)
    {
        Config config;
        config.FromString(configline);
        PR_LOG(PR_LOG_DEBUG, "entry");
        m_readDir = config.ReadDir.Value();
        m_storeLocation = config.StoreLocation.Value();

        svpGetDrmStoragePath(m_readDir, m_storePath, m_storeLocation);
 
        PR_LOG(PR_LOG_DEBUG, "m_storeLocation[%s] m_storePath[%s] m_readDir[%s]", m_storeLocation.c_str(), 
                                                        m_storePath.c_str(),
                                                        m_readDir.c_str() );
        WPEFramework::Core::Directory(m_storePath.c_str()).CreatePath();
        WPEFramework::Core::Directory(m_readDir.c_str()).CreatePath();

        string homePath = config.HomePath.Value();
        if(!homePath.empty()) {
            WPEFramework::Core::SystemInfo::SetEnvironment(_T("HOME"), homePath.c_str());
        } else {
            PR_LOG(PR_LOG_WARN, "could not set HOME variable. SecureStop functionality may not work!");
        }

        CreateSystemExt();

        InitSystemExt();
        PR_LOG(PR_LOG_DEBUG, "exit");
    }

    void Initialize(const WPEFramework::PluginHost::IShell * service, const std::string& configline)
    {
        InitializeLogLevel();
        PR_LOG(PR_LOG_DEBUG, "entry");
        /* We can do SoC specific requirement for Playready */
        svpPlatformInitializePlayready();
        OnSystemConfigurationAvailable(configline);
        PR_LOG(PR_LOG_DEBUG, "exit");
    }

private:
    DRM_WCHAR* drmdir_;

    std::unordered_map<std::string /*key system id*/, std::unique_ptr<KeySystemCtx>> m_keySystemCtxs;

    string m_readDir;
    string m_storeLocation;
    string m_storePath;

    DRM_BYTE *m_pbPublisherCert = nullptr;
    DRM_DWORD m_cbPublisherCert = 0;
    uint32_t m_sessionCount = 0;
    uint32_t m_sessionId = 0;
    std::map<uint32_t, IMediaKeySession*> m_sessionMap;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
