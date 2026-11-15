#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <ks.h>
#include <ksmedia.h>
#include <propidl.h>
#include <cmath>
#include <vector>
#include <cstdio>
#include <cstdarg>

// ============================================================================
// 1. THREAD-SAFE LOGGING & CRASH DIAGNOSTIC HANDLER
// ============================================================================
static CRITICAL_SECTION g_LogLock;
static CRITICAL_SECTION g_HookLock;
static volatile LONG g_LogInit = 0;
static HMODULE g_hSelfModule = nullptr;

static void InitLog() {
    if (InterlockedCompareExchange(&g_LogInit, 1, 0) == 0) {
        InitializeCriticalSection(&g_LogLock);
        InitializeCriticalSection(&g_HookLock);
        DeleteFileA("u4_spatial_proxy.log");
    }
}

static void LogMsg(const char* fmt, ...) {
    if (InterlockedCompareExchange(&g_LogInit, 0, 0) == 0) return;
    EnterCriticalSection(&g_LogLock);
    FILE* f = fopen("u4_spatial_proxy.log", "a");
    if (f) {
        DWORD tid = GetCurrentThreadId();
        fprintf(f, "[T:%04X] ", (unsigned)tid);
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fflush(f);
        fclose(f);
    }
    LeaveCriticalSection(&g_LogLock);
}

static LONG WINAPI CrashDiagnosticHandler(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    // Ignore benign exceptions (OutputDebugString, thread naming, C++ exceptions, breakpoints)
    if (code == 0x40010006 || code == 0x4001000A || code == 0x406D1388 ||
        code == 0xE06D7363 || code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    HMODULE hFaultMod = nullptr;
    char modName[MAX_PATH] = " <unknown>";
    uintptr_t faultAddr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
    uintptr_t modBase = 0;

    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(faultAddr),
            &hFaultMod) && hFaultMod)
    {
        modBase = reinterpret_cast<uintptr_t>(hFaultMod);
        GetModuleFileNameA(hFaultMod, modName, MAX_PATH);
    }

    LogMsg("================================================================");
    LogMsg("[CRASH] Exception 0x%08X at 0x%016llX (Module: %s + 0x%llX)",
           (unsigned)code,
           (unsigned long long)faultAddr,
           modName,
           (unsigned long long)(faultAddr - modBase));
    if (ep->ExceptionRecord->NumberParameters >= 2) {
        LogMsg("[CRASH] Access Type: %llu (0=Read, 1=Write, 8=Exec), Target Address: 0x%016llX",
               (unsigned long long)ep->ExceptionRecord->ExceptionInformation[0],
               (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1]);
    }
    CONTEXT* c = ep->ContextRecord;
    LogMsg("[CRASH] RIP=0x%016llX RSP=0x%016llX RBP=0x%016llX",
           (unsigned long long)c->Rip, (unsigned long long)c->Rsp, (unsigned long long)c->Rbp);
    LogMsg("[CRASH] RAX=0x%016llX RBX=0x%016llX RCX=0x%016llX RDX=0x%016llX",
           (unsigned long long)c->Rax, (unsigned long long)c->Rbx, (unsigned long long)c->Rcx, (unsigned long long)c->Rdx);
    LogMsg("[CRASH] RSI=0x%016llX RDI=0x%016llX R8 =0x%016llX R9 =0x%016llX",
           (unsigned long long)c->Rsi, (unsigned long long)c->Rdi, (unsigned long long)c->R8, (unsigned long long)c->R9);
    LogMsg("================================================================");

    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================================
// 2. GUID DEFINITIONS (WIN7 / WIN8 / WIN10 AUDIO INTERFACES)
// ============================================================================

// {1CB9AD4C-DBFA-4c32-B178-C2F568A703B2} - IID_IAudioClient (Win7)
static const GUID IID_IAudioClient_Win7 =
    { 0x1CB9AD4C, 0xDBFA, 0x4c32, { 0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2 } };

// {726778CD-F60A-4EDA-82DE-E47610CD78AA} - IID_IAudioClient2 (Win8+)
static const GUID IID_IAudioClient2_Win8 =
    { 0x726778CD, 0xF60A, 0x4EDA, { 0x82, 0xDE, 0xE4, 0x76, 0x10, 0xCD, 0x78, 0xAA } };

// {7ED4EE07-8E67-4CD4-8C1A-2B7A5987AD42} - IID_IAudioClient3 (Win10+)
static const GUID IID_IAudioClient3_Win10 =
    { 0x7ED4EE07, 0x8E67, 0x4CD4, { 0x8C, 0x1A, 0x2B, 0x7A, 0x59, 0x87, 0xAD, 0x42 } };

// {F294ACFC-3146-4483-A7BF-ADDCA7C260E2} - IID_IAudioRenderClient
static const GUID IID_IAudioRenderClient_Win7 =
    { 0xF294ACFC, 0x3146, 0x4483, { 0xA7, 0xBF, 0xAD, 0xDC, 0xA7, 0xC2, 0x60, 0xE2 } };

// {BCDE0395-E52F-467C-8E3D-C4579291692E} - CLSID_MMDeviceEnumerator
static const GUID CLSID_MMDeviceEnumerator_Win7 =
    { 0xBCDE0395, 0xE52F, 0x467C, { 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E } };

// {A95664D2-9614-4F35-A746-DE8DB63617E6} - IID_IMMDeviceEnumerator
static const GUID IID_IMMDeviceEnumerator_Win7 =
    { 0xA95664D2, 0x9614, 0x4F35, { 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6 } };

// {DC8E63F3-D12B-4952-B47B-5E45026A862D} - Requested by u4.exe for SpatialAudio
static const GUID IID_ISpatialAudioClient_U4 =
    { 0xDC8E63F3, 0xD12B, 0x4952, { 0xB4, 0x7B, 0x5E, 0x45, 0x02, 0x6A, 0x86, 0x2D } };

// {BBF8E066-AAAA-49BE-9A4D-FD2A858EA27F} - Standard SDK IID_ISpatialAudioClient
static const GUID IID_ISpatialAudioClient_SDK =
    { 0xBBF8E066, 0xAAAA, 0x49BE, { 0x9A, 0x4D, 0xFD, 0x2A, 0x85, 0x8E, 0xA2, 0x7F } };

// {DCDAA858-895A-4A22-A5EB-67BDA506096D} - IID_IAudioFormatEnumerator
static const GUID IID_IAudioFormatEnumerator_Custom =
    { 0xDCDAA858, 0x895A, 0x4A22, { 0xA5, 0xEB, 0x67, 0xBD, 0xA5, 0x06, 0x09, 0x6D } };

// {BAB5F473-B423-477B-85F5-B5A332A04153} - IID_ISpatialAudioObjectRenderStream
static const GUID IID_ISpatialAudioObjectRenderStream_Custom =
    { 0xBAB5F473, 0xB423, 0x477B, { 0x85, 0xF5, 0xB5, 0xA3, 0x32, 0xA0, 0x41, 0x53 } };

// {2EAFEB77-B97A-4C7D-84F8-50797864549B} - IID_ISpatialAudioObjectRenderStreamBase
static const GUID IID_ISpatialAudioObjectRenderStreamBase_Custom =
    { 0x2EAFEB77, 0xB97A, 0x4C7D, { 0x84, 0xF8, 0x50, 0x79, 0x78, 0x64, 0x54, 0x9B } };

// {DDE28967-521B-46E5-8F00-BD6F2BC8AB1D} - IID_ISpatialAudioObject
static const GUID IID_ISpatialAudioObject_Custom =
    { 0xDDE28967, 0x521B, 0x46E5, { 0x8F, 0x00, 0xBD, 0x6F, 0x2B, 0xC8, 0xAB, 0x1D } };

// {CCE0B8F2-8D4D-4EFB-A8CF-3D6ECF1C30E0} - IID_ISpatialAudioObjectBase
static const GUID IID_ISpatialAudioObjectBase_Custom =
    { 0xCCE0B8F2, 0x8D4D, 0x4EFB, { 0xA8, 0xCF, 0x3D, 0x6E, 0xCF, 0x1C, 0x30, 0xE0 } };

// ============================================================================
// 3. PER-VTABLE ORIGINAL POINTER REGISTRY (PREVENTS RECURSION & VTABLE MISMATCH)
// ============================================================================
struct VtableHookEntry {
    void** vtable;
    void* origSlot3;
    void* origSlot4;
    void* origSlot5;
};

static VtableHookEntry g_VtableHooks[64];
static size_t g_VtableHookCount = 0;

static VtableHookEntry* GetOrCreateVtableEntry(void** vtable) {
    for (size_t i = 0; i < g_VtableHookCount; ++i) {
        if (g_VtableHooks[i].vtable == vtable) {
            return &g_VtableHooks[i];
        }
    }
    if (g_VtableHookCount >= 64) return nullptr;
    VtableHookEntry* entry = &g_VtableHooks[g_VtableHookCount++];
    entry->vtable = vtable;
    entry->origSlot3 = nullptr;
    entry->origSlot4 = nullptr;
    entry->origSlot5 = nullptr;
    return entry;
}

static void* GetOrigVtableSlot(void* pThis, int slotIndex, void* fallbackFn) {
    if (!pThis) return fallbackFn;
    void** vtable = *reinterpret_cast<void***>(pThis);
    if (!vtable) return fallbackFn;

    EnterCriticalSection(&g_HookLock);
    void* result = nullptr;
    for (size_t i = 0; i < g_VtableHookCount; ++i) {
        if (g_VtableHooks[i].vtable == vtable) {
            if (slotIndex == 3) result = g_VtableHooks[i].origSlot3;
            else if (slotIndex == 4) result = g_VtableHooks[i].origSlot4;
            else if (slotIndex == 5) result = g_VtableHooks[i].origSlot5;
            break;
        }
    }
    LeaveCriticalSection(&g_HookLock);
    return result ? result : fallbackFn;
}

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDevice_Activate)(
    IMMDevice* This, REFIID iid, DWORD dwClsCtx, PROPVARIANT* pActivationParams, void** ppInterface);
static PFN_IMMDevice_Activate g_FallbackActivate = nullptr;

// Thread-local flag so internal raw IAudioClient activations bypass the hook cleanly
static __thread bool tls_BypassActivateHook = false;

static HRESULT CallRealDeviceActivate(
    IMMDevice* This,
    REFIID iid,
    DWORD dwClsCtx,
    PROPVARIANT* pActivationParams,
    void** ppInterface)
{
    PFN_IMMDevice_Activate origFn = reinterpret_cast<PFN_IMMDevice_Activate>(
        GetOrigVtableSlot(This, 3, reinterpret_cast<void*>(g_FallbackActivate)));
    if (!origFn) return E_FAIL;
    tls_BypassActivateHook = true;
    HRESULT hr = origFn(This, iid, dwClsCtx, pActivationParams, ppInterface);
    tls_BypassActivateHook = false;
    return hr;
}

// ============================================================================
// 4. WINDOWS 8/10 IAUDIOCLIENT2 & IAUDIOCLIENT3 WRAPPER OVER WIN7 IAUDIOCLIENT
// ============================================================================

struct AudioClientProperties_Custom {
    UINT32 cbSize;
    BOOL bIsOffload;
    int eCategory;
    int Options;
};

struct IAudioClient3_Custom : public IAudioClient {
    // IAudioClient2 methods (vtable indices 12..14)
    virtual HRESULT STDMETHODCALLTYPE IsOffloadCapable(int Category, BOOL* pbOffloadCapable) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetClientProperties(const AudioClientProperties_Custom* pProperties) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetBufferSizeLimits(
        const WAVEFORMATEX* pFormat,
        BOOL bEventDriven,
        REFERENCE_TIME* phnsMinBufferDuration,
        REFERENCE_TIME* phnsMaxBufferDuration) = 0;

    // IAudioClient3 methods (vtable indices 15..17)
    virtual HRESULT STDMETHODCALLTYPE GetSharedModeEnginePeriod(
        const WAVEFORMATEX* pFormat,
        UINT32* pDefaultPeriodInFrames,
        UINT32* pFundamentalPeriodInFrames,
        UINT32* pMinPeriodInFrames,
        UINT32* pMaxPeriodInFrames) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentSharedModeEnginePeriod(
        WAVEFORMATEX** ppFormat,
        UINT32* pCurrentPeriodInFrames) = 0;
    virtual HRESULT STDMETHODCALLTYPE InitializeSharedAudioStream(
        DWORD StreamFlags,
        UINT32 PeriodInFrames,
        const WAVEFORMATEX* pFormat,
        LPCGUID AudioSessionGuid) = 0;
};

class FakeAudioClient23 : public IAudioClient3_Custom {
    LONG m_refCount;
    IAudioClient* m_real;

public:
    FakeAudioClient23(IAudioClient* realClient) : m_refCount(1), m_real(realClient) {
        if (m_real) m_real->AddRef();
    }

    virtual ~FakeAudioClient23() {
        if (m_real) m_real->Release();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown ||
            riid == IID_IAudioClient_Win7 ||
            riid == IID_IAudioClient2_Win8 ||
            riid == IID_IAudioClient3_Win10) {
            *ppvObject = static_cast<IAudioClient3_Custom*>(this);
            AddRef();
            return S_OK;
        }
        return m_real ? m_real->QueryInterface(riid, ppvObject) : E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) delete this;
        return ref;
    }

    HRESULT STDMETHODCALLTYPE Initialize(
        AUDCLNT_SHAREMODE ShareMode,
        DWORD StreamFlags,
        REFERENCE_TIME hnsBufferDuration,
        REFERENCE_TIME hnsPeriodicity,
        const WAVEFORMATEX* pFormat,
        LPCGUID AudioSessionGuid) override
    {
        // Strip AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM (0x80000000) & SRC_DEFAULT_QUALITY (0x08000000) if Win7 rejects them
        DWORD cleanFlags = StreamFlags & ~(0x80000000 | 0x08000000 | 0x40000000);
        HRESULT hr = m_real->Initialize(ShareMode, cleanFlags, hnsBufferDuration, hnsPeriodicity, pFormat, AudioSessionGuid);
        if (FAILED(hr)) {
            // Try with original flags in case Win7 SP1 supports AUTOCONVERTPCM
            hr = m_real->Initialize(ShareMode, StreamFlags, hnsBufferDuration, hnsPeriodicity, pFormat, AudioSessionGuid);
        }
        if (FAILED(hr) && hnsBufferDuration < 300000) {
            // Fallback if 10ms duration (100000) is smaller than Win7's minimum shared buffer
            hr = m_real->Initialize(ShareMode, cleanFlags, 300000, hnsPeriodicity, pFormat, AudioSessionGuid);
        }
        LogMsg("[IAudioClient2/3] Initialize(ShareMode=%d, Flags=0x%X, Duration=%lld) -> 0x%08X",
               (int)ShareMode, (unsigned)StreamFlags, (long long)hnsBufferDuration, (unsigned)hr);
        return hr;
    }

    HRESULT STDMETHODCALLTYPE GetBufferSize(UINT32* pNumBufferFrames) override {
        return m_real->GetBufferSize(pNumBufferFrames);
    }

    HRESULT STDMETHODCALLTYPE GetStreamLatency(REFERENCE_TIME* phnsLatency) override {
        return m_real->GetStreamLatency(phnsLatency);
    }

    HRESULT STDMETHODCALLTYPE GetCurrentPadding(UINT32* pNumPaddingFrames) override {
        return m_real->GetCurrentPadding(pNumPaddingFrames);
    }

    HRESULT STDMETHODCALLTYPE IsFormatSupported(
        AUDCLNT_SHAREMODE ShareMode,
        const WAVEFORMATEX* pFormat,
        WAVEFORMATEX** ppClosestMatch) override
    {
        return m_real->IsFormatSupported(ShareMode, pFormat, ppClosestMatch);
    }

    HRESULT STDMETHODCALLTYPE GetMixFormat(WAVEFORMATEX** ppDeviceFormat) override {
        return m_real->GetMixFormat(ppDeviceFormat);
    }

    HRESULT STDMETHODCALLTYPE GetDevicePeriod(
        REFERENCE_TIME* phnsDefaultDevicePeriod,
        REFERENCE_TIME* phnsMinimumDevicePeriod) override
    {
        return m_real->GetDevicePeriod(phnsDefaultDevicePeriod, phnsMinimumDevicePeriod);
    }

    HRESULT STDMETHODCALLTYPE Start(void) override {
        LogMsg("[IAudioClient2/3] Start() called");
        return m_real->Start();
    }

    HRESULT STDMETHODCALLTYPE Stop(void) override {
        LogMsg("[IAudioClient2/3] Stop() called");
        return m_real->Stop();
    }

    HRESULT STDMETHODCALLTYPE Reset(void) override {
        LogMsg("[IAudioClient2/3] Reset() called");
        return m_real->Reset();
    }

    HRESULT STDMETHODCALLTYPE SetEventHandle(HANDLE eventHandle) override {
        LogMsg("[IAudioClient2/3] SetEventHandle(%p) called", eventHandle);
        return m_real->SetEventHandle(eventHandle);
    }

    HRESULT STDMETHODCALLTYPE GetService(REFIID riid, void** ppv) override {
        HRESULT hr = m_real->GetService(riid, ppv);
        LogMsg("[IAudioClient2/3] GetService(Data1=0x%08X) -> 0x%08X", (unsigned)riid.Data1, (unsigned)hr);
        return hr;
    }

    HRESULT STDMETHODCALLTYPE IsOffloadCapable(int Category, BOOL* pbOffloadCapable) override {
        if (!pbOffloadCapable) return E_POINTER;
        *pbOffloadCapable = FALSE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetClientProperties(const AudioClientProperties_Custom* pProperties) override {
        if (!pProperties) return E_POINTER;
        LogMsg("[IAudioClient2/3] SetClientProperties(cbSize=%u, Category=%d, Options=0x%X) -> S_OK",
               pProperties->cbSize, pProperties->eCategory, pProperties->Options);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetBufferSizeLimits(
        const WAVEFORMATEX* pFormat,
        BOOL bEventDriven,
        REFERENCE_TIME* phnsMinBufferDuration,
        REFERENCE_TIME* phnsMaxBufferDuration) override
    {
        if (!phnsMinBufferDuration || !phnsMaxBufferDuration) return E_POINTER;
        REFERENCE_TIME defPeriod = 100000, minPeriod = 30000;
        if (m_real) {
            m_real->GetDevicePeriod(&defPeriod, &minPeriod);
        }
        *phnsMinBufferDuration = defPeriod ? defPeriod : 100000;
        *phnsMaxBufferDuration = 20000000;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetSharedModeEnginePeriod(
        const WAVEFORMATEX* pFormat,
        UINT32* pDefaultPeriodInFrames,
        UINT32* pFundamentalPeriodInFrames,
        UINT32* pMinPeriodInFrames,
        UINT32* pMaxPeriodInFrames) override
    {
        if (!pDefaultPeriodInFrames || !pFundamentalPeriodInFrames || !pMinPeriodInFrames || !pMaxPeriodInFrames)
            return E_POINTER;

        UINT32 sampleRate = (pFormat && pFormat->nSamplesPerSec) ? pFormat->nSamplesPerSec : 48000;
        UINT32 frames = sampleRate / 100;
        REFERENCE_TIME defPeriod = 0, minPeriod = 0;
        if (m_real && SUCCEEDED(m_real->GetDevicePeriod(&defPeriod, &minPeriod)) && defPeriod > 0) {
            frames = static_cast<UINT32>((defPeriod * sampleRate) / 10000000ULL);
        }
        if (frames == 0) frames = 480;

        *pDefaultPeriodInFrames = frames;
        *pFundamentalPeriodInFrames = 1;
        *pMinPeriodInFrames = frames;
        *pMaxPeriodInFrames = frames;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetCurrentSharedModeEnginePeriod(
        WAVEFORMATEX** ppFormat,
        UINT32* pCurrentPeriodInFrames) override
    {
        if (!ppFormat || !pCurrentPeriodInFrames) return E_POINTER;
        HRESULT hr = m_real->GetMixFormat(ppFormat);
        if (FAILED(hr) || !*ppFormat) return hr;

        UINT32 sampleRate = (*ppFormat)->nSamplesPerSec ? (*ppFormat)->nSamplesPerSec : 48000;
        UINT32 frames = sampleRate / 100;
        REFERENCE_TIME defPeriod = 0, minPeriod = 0;
        if (SUCCEEDED(m_real->GetDevicePeriod(&defPeriod, &minPeriod)) && defPeriod > 0) {
            frames = static_cast<UINT32>((defPeriod * sampleRate) / 10000000ULL);
        }
        *pCurrentPeriodInFrames = frames ? frames : 480;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE InitializeSharedAudioStream(
        DWORD StreamFlags,
        UINT32 PeriodInFrames,
        const WAVEFORMATEX* pFormat,
        LPCGUID AudioSessionGuid) override
    {
        UINT32 sampleRate = (pFormat && pFormat->nSamplesPerSec) ? pFormat->nSamplesPerSec : 48000;
        REFERENCE_TIME duration = (static_cast<REFERENCE_TIME>(PeriodInFrames) * 10000000ULL) / sampleRate;
        if (duration < 200000) duration = 200000;
        return Initialize(AUDCLNT_SHAREMODE_SHARED, StreamFlags, duration, 0, pFormat, AudioSessionGuid);
    }
};

// ============================================================================
// 5. WINDOWS 10 SPATIAL AUDIO STRUCTURES & INTERFACES
// ============================================================================

typedef enum AudioObjectType {
    AudioObjectType_None             = 0,
    AudioObjectType_Dynamic          = (1 << 0),
    AudioObjectType_FrontLeft        = (1 << 1),
    AudioObjectType_FrontRight       = (1 << 2),
    AudioObjectType_FrontCenter      = (1 << 3),
    AudioObjectType_LowFrequency     = (1 << 4),
    AudioObjectType_SideLeft         = (1 << 5),
    AudioObjectType_SideRight        = (1 << 6),
    AudioObjectType_BackLeft         = (1 << 7),
    AudioObjectType_BackRight        = (1 << 8),
    AudioObjectType_TopFrontLeft     = (1 << 9),
    AudioObjectType_TopFrontRight    = (1 << 10),
    AudioObjectType_TopBackLeft      = (1 << 11),
    AudioObjectType_TopBackRight     = (1 << 12),
    AudioObjectType_BottomFrontLeft  = (1 << 13),
    AudioObjectType_BottomFrontRight = (1 << 14),
    AudioObjectType_BottomBackLeft   = (1 << 15),
    AudioObjectType_BottomBackRight  = (1 << 16),
    AudioObjectType_BackCenter       = (1 << 17)
} AudioObjectType;

struct ISpatialAudioObjectRenderStreamNotify : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE OnAvailableDynamicObjectCountChange(
        IUnknown* sender, LONGLONG hnsComplianceDeadlineTime, UINT32 availableDynamicObjectCountChange) = 0;
};

struct SpatialAudioObjectRenderStreamActivationParams_Aligned {
    const WAVEFORMATEX* ObjectFormat;
    AudioObjectType StaticObjectTypeMask;
    UINT32 MinDynamicObjectCount;
    UINT32 MaxDynamicObjectCount;
    int Category;
    HANDLE EventHandle;
    ISpatialAudioObjectRenderStreamNotify* NotifyObject;
};

struct IAudioFormatEnumerator : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetCount(UINT32* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetFormat(UINT32 index, WAVEFORMATEX** format) = 0;
};

struct ISpatialAudioObject : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetBuffer(BYTE** buffer, UINT32* bufferLength) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetEndOfStream(UINT32 frameCount) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsActive(BOOL* isActive) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAudioObjectType(AudioObjectType* audioObjectType) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetPosition(float x, float y, float z) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetVolume(float volume) = 0;
};

struct ISpatialAudioObjectRenderStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetAvailableDynamicObjectCount(UINT32* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetService(REFIID riid, void** service) = 0;
    virtual HRESULT STDMETHODCALLTYPE Start(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Stop(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Reset(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE BeginUpdatingAudioObjects(UINT32* availableDynamicObjectCount, UINT32* frameCountPerBuffer) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndUpdatingAudioObjects(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE ActivateSpatialAudioObject(AudioObjectType type, ISpatialAudioObject** audioObject) = 0;
};

struct ISpatialAudioClient : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetStaticObjectPosition(AudioObjectType type, float* x, float* y, float* z) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNativeStaticObjectTypeMask(AudioObjectType* mask) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetMaxDynamicObjectCount(UINT32* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetSupportedAudioObjectFormatEnumerator(IAudioFormatEnumerator** enumerator) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetMaxFrameCount(const WAVEFORMATEX* objectFormat, UINT32* frameCountPerBuffer) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsAudioObjectFormatSupported(const WAVEFORMATEX* objectFormat) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsSpatialAudioStreamAvailable(REFIID streamUuid, const PROPVARIANT* auxiliaryInfo) = 0;
    virtual HRESULT STDMETHODCALLTYPE ActivateSpatialAudioStream(const PROPVARIANT* activationParams, REFIID riid, void** stream) = 0;
};

// ============================================================================
// 6. SPATIAL AUDIO EMULATION IMPLEMENTATIONS (DOWNMIX TO WIN7 WASAPI)
// ============================================================================

class FakeAudioFormatEnumerator : public IAudioFormatEnumerator {
    LONG m_refCount;
    WAVEFORMATEX m_format;
public:
    FakeAudioFormatEnumerator(UINT32 sampleRate) : m_refCount(1) {
        m_format.wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
        m_format.nChannels = 1;
        m_format.nSamplesPerSec = sampleRate ? sampleRate : 48000;
        m_format.wBitsPerSample = 32;
        m_format.nBlockAlign = 4;
        m_format.nAvgBytesPerSec = m_format.nSamplesPerSec * m_format.nBlockAlign;
        m_format.cbSize = 0;
    }

    virtual ~FakeAudioFormatEnumerator() {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IAudioFormatEnumerator_Custom) {
            *ppvObject = static_cast<IAudioFormatEnumerator*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) delete this;
        return ref;
    }

    HRESULT STDMETHODCALLTYPE GetCount(UINT32* count) override {
        if (!count) return E_POINTER;
        *count = 1;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetFormat(UINT32 index, WAVEFORMATEX** format) override {
        if (!format) return E_POINTER;
        if (index != 0) return E_INVALIDARG;
        *format = &m_format;
        return S_OK;
    }
};

class FakeSpatialAudioObject : public ISpatialAudioObject {
public:
    LONG m_refCount;
    AudioObjectType m_type;
    float m_x, m_y, m_z;
    float m_volume;
    BOOL m_isActive;
    BOOL m_endOfStream;
    std::vector<float> m_buffer;
    UINT32 m_validFrames;

    FakeSpatialAudioObject(AudioObjectType type, UINT32 maxFrames)
        : m_refCount(1), m_type(type), m_x(0.0f), m_y(0.0f), m_z(0.0f),
          m_volume(1.0f), m_isActive(TRUE), m_endOfStream(FALSE), m_validFrames(480) {
        m_buffer.resize(maxFrames ? maxFrames : 4096, 0.0f);
    }

    virtual ~FakeSpatialAudioObject() {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown ||
            riid == IID_ISpatialAudioObject_Custom ||
            riid == IID_ISpatialAudioObjectBase_Custom) {
            *ppvObject = static_cast<ISpatialAudioObject*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) delete this;
        return ref;
    }

    HRESULT STDMETHODCALLTYPE GetBuffer(BYTE** buffer, UINT32* bufferLength) override {
        if (!buffer || !bufferLength) return E_POINTER;
        if (!m_isActive) {
            *buffer = nullptr;
            *bufferLength = 0;
            return S_OK;
        }
        UINT32 frames = m_validFrames;
        if (frames > m_buffer.size()) {
            m_buffer.resize(frames, 0.0f);
        }
        if (frames > 0) {
            memset(m_buffer.data(), 0, frames * sizeof(float));
        }
        *buffer = reinterpret_cast<BYTE*>(m_buffer.data());
        *bufferLength = frames * sizeof(float);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetEndOfStream(UINT32 frameCount) override {
        m_validFrames = frameCount;
        m_endOfStream = TRUE;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE IsActive(BOOL* isActive) override {
        if (!isActive) return E_POINTER;
        *isActive = m_isActive;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetAudioObjectType(AudioObjectType* audioObjectType) override {
        if (!audioObjectType) return E_POINTER;
        *audioObjectType = m_type;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetPosition(float x, float y, float z) override {
        m_x = x; m_y = y; m_z = z;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetVolume(float volume) override {
        m_volume = volume;
        return S_OK;
    }
};

class FakeSpatialAudioObjectRenderStream : public ISpatialAudioObjectRenderStream {
    LONG m_refCount;
    IAudioClient* m_audioClient;
    IAudioRenderClient* m_renderClient;
    WAVEFORMATEX* m_mixFormat;
    UINT32 m_bufferFrameCount;
    UINT32 m_periodFrames;
    UINT32 m_maxDynamicObjects;
    HANDLE m_gameEvent;
    HANDLE m_stopEvent;
    HANDLE m_pumpThread;
    CRITICAL_SECTION m_lock;
    std::vector<FakeSpatialAudioObject*> m_objects;
    UINT32 m_currentUpdateFrames;
    volatile LONG m_running;
    bool m_loggedFirstUpdate;
    bool m_loggedFirstObject;

    static DWORD WINAPI PumpThreadProc(LPVOID param) {
        FakeSpatialAudioObjectRenderStream* self = static_cast<FakeSpatialAudioObjectRenderStream*>(param);
        self->PumpLoop();
        return 0;
    }

    void PumpLoop() {
        while (WaitForSingleObject(m_stopEvent, 10) == WAIT_TIMEOUT) {
            if (InterlockedCompareExchange(&m_running, 0, 0) != 0 && m_gameEvent) {
                SetEvent(m_gameEvent);
            }
        }
    }

    static void ComputeStereoGains(FakeSpatialAudioObject* obj, float& outGainL, float& outGainR) {
        float vol = obj->m_volume;
        if (vol <= 0.0f) {
            outGainL = 0.0f; outGainR = 0.0f;
            return;
        }

        switch (obj->m_type) {
            case AudioObjectType_FrontLeft:
                outGainL = 1.0f; outGainR = 0.0f; break;
            case AudioObjectType_FrontRight:
                outGainL = 0.0f; outGainR = 1.0f; break;
            case AudioObjectType_FrontCenter:
                outGainL = 0.7071f; outGainR = 0.7071f; break;
            case AudioObjectType_LowFrequency:
                outGainL = 0.5f; outGainR = 0.5f; break;
            case AudioObjectType_SideLeft:
            case AudioObjectType_BackLeft:
            case AudioObjectType_TopFrontLeft:
            case AudioObjectType_TopBackLeft:
            case AudioObjectType_BottomFrontLeft:
            case AudioObjectType_BottomBackLeft:
                outGainL = 0.7071f; outGainR = 0.0f; break;
            case AudioObjectType_SideRight:
            case AudioObjectType_BackRight:
            case AudioObjectType_TopFrontRight:
            case AudioObjectType_TopBackRight:
            case AudioObjectType_BottomFrontRight:
            case AudioObjectType_BottomBackRight:
                outGainL = 0.0f; outGainR = 0.7071f; break;
            case AudioObjectType_BackCenter:
                outGainL = 0.5f; outGainR = 0.5f; break;
            case AudioObjectType_Dynamic:
            default: {
                float distSq = obj->m_x * obj->m_x + obj->m_y * obj->m_y + obj->m_z * obj->m_z;
                float dist = sqrtf(distSq);
                float atten = 1.0f / (1.0f + 0.15f * dist);
                float pan = (dist > 0.0001f) ? (obj->m_x / dist) : 0.0f;
                if (pan < -1.0f) pan = -1.0f;
                if (pan > 1.0f) pan = 1.0f;
                float angle = (pan + 1.0f) * 0.78539816f;
                outGainL = cosf(angle) * atten;
                outGainR = sinf(angle) * atten;
                break;
            }
        }
        outGainL *= vol;
        outGainR *= vol;
    }

public:
    FakeSpatialAudioObjectRenderStream(
        IAudioClient* audioClient,
        IAudioRenderClient* renderClient,
        WAVEFORMATEX* mixFormat,
        UINT32 bufferFrameCount,
        UINT32 periodFrames,
        UINT32 maxDynamicObjects,
        HANDLE gameEvent)
        : m_refCount(1),
          m_audioClient(audioClient),
          m_renderClient(renderClient),
          m_mixFormat(mixFormat),
          m_bufferFrameCount(bufferFrameCount),
          m_periodFrames(periodFrames),
          m_maxDynamicObjects(maxDynamicObjects ? maxDynamicObjects : 128),
          m_gameEvent(gameEvent),
          m_stopEvent(nullptr),
          m_pumpThread(nullptr),
          m_currentUpdateFrames(periodFrames),
          m_running(0),
          m_loggedFirstUpdate(false),
          m_loggedFirstObject(false)
    {
        InitializeCriticalSection(&m_lock);
        if (m_audioClient) m_audioClient->AddRef();
        if (m_renderClient) m_renderClient->AddRef();

        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        m_pumpThread = CreateThread(nullptr, 0, PumpThreadProc, this, 0, nullptr);
    }

    virtual ~FakeSpatialAudioObjectRenderStream() {
        LogMsg("[Stream] ~FakeSpatialAudioObjectRenderStream() destroying stream %p", this);
        InterlockedExchange(&m_running, 0);
        if (m_stopEvent) SetEvent(m_stopEvent);
        if (m_pumpThread) {
            WaitForSingleObject(m_pumpThread, 500);
            CloseHandle(m_pumpThread);
        }
        if (m_stopEvent) CloseHandle(m_stopEvent);

        EnterCriticalSection(&m_lock);
        for (size_t i = 0; i < m_objects.size(); ++i) {
            m_objects[i]->Release();
        }
        m_objects.clear();
        LeaveCriticalSection(&m_lock);
        DeleteCriticalSection(&m_lock);

        if (m_mixFormat) CoTaskMemFree(m_mixFormat);
        if (m_renderClient) m_renderClient->Release();
        if (m_audioClient) m_audioClient->Release();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown ||
            riid == IID_ISpatialAudioObjectRenderStream_Custom ||
            riid == IID_ISpatialAudioObjectRenderStreamBase_Custom) {
            *ppvObject = static_cast<ISpatialAudioObjectRenderStream*>(this);
            AddRef();
            return S_OK;
        }
        LogMsg("[Stream] QueryInterface for unknown IID Data1=0x%08X", (unsigned)riid.Data1);
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) delete this;
        return ref;
    }

    HRESULT STDMETHODCALLTYPE GetAvailableDynamicObjectCount(UINT32* value) override {
        if (!value) return E_POINTER;
        EnterCriticalSection(&m_lock);
        UINT32 activeDyn = 0;
        for (size_t i = 0; i < m_objects.size(); ++i) {
            if (m_objects[i]->m_isActive && m_objects[i]->m_type == AudioObjectType_Dynamic) {
                activeDyn++;
            }
        }
        *value = (m_maxDynamicObjects > activeDyn) ? (m_maxDynamicObjects - activeDyn) : 0;
        LeaveCriticalSection(&m_lock);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetService(REFIID riid, void** service) override {
        LogMsg("[Stream] GetService(Data1=0x%08X)", (unsigned)riid.Data1);
        if (!m_audioClient) return E_FAIL;
        return m_audioClient->GetService(riid, service);
    }

    HRESULT STDMETHODCALLTYPE Start(void) override {
        LogMsg("[Stream] Start() called on %p", this);
        InterlockedExchange(&m_running, 1);
        if (m_gameEvent) SetEvent(m_gameEvent);
        return m_audioClient ? m_audioClient->Start() : S_OK;
    }

    HRESULT STDMETHODCALLTYPE Stop(void) override {
        LogMsg("[Stream] Stop() called on %p", this);
        InterlockedExchange(&m_running, 0);
        return m_audioClient ? m_audioClient->Stop() : S_OK;
    }

    HRESULT STDMETHODCALLTYPE Reset(void) override {
        LogMsg("[Stream] Reset() called on %p", this);
        return m_audioClient ? m_audioClient->Reset() : S_OK;
    }

    HRESULT STDMETHODCALLTYPE BeginUpdatingAudioObjects(
        UINT32* availableDynamicObjectCount,
        UINT32* frameCountPerBuffer) override
    {
        EnterCriticalSection(&m_lock);

        // Windows 10 Spatial Audio engines always expect a consistent period frame count
        // (e.g., 480 frames = 10ms at 48kHz) during BeginUpdatingAudioObjects.
        // Returning 0 when padding is full can cause divide-by-zero or null buffer crashes in game mixers!
        m_currentUpdateFrames = m_periodFrames;

        UINT32 activeDyn = 0;
        for (size_t i = 0; i < m_objects.size(); ++i) {
            FakeSpatialAudioObject* obj = m_objects[i];
            if (obj->m_isActive) {
                obj->m_validFrames = m_currentUpdateFrames;
                if (obj->m_type == AudioObjectType_Dynamic) activeDyn++;
            }
        }

        if (availableDynamicObjectCount) {
            *availableDynamicObjectCount = (m_maxDynamicObjects > activeDyn) ? (m_maxDynamicObjects - activeDyn) : 0;
        }
        if (frameCountPerBuffer) {
            *frameCountPerBuffer = m_currentUpdateFrames;
        }

        if (!m_loggedFirstUpdate) {
            m_loggedFirstUpdate = true;
            LogMsg("[Stream] First BeginUpdatingAudioObjects(availDyn=%u, frames=%u)",
                   (m_maxDynamicObjects > activeDyn) ? (m_maxDynamicObjects - activeDyn) : 0,
                   m_currentUpdateFrames);
        }

        LeaveCriticalSection(&m_lock);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE EndUpdatingAudioObjects(void) override {
        EnterCriticalSection(&m_lock);

        UINT32 padding = 0;
        UINT32 availFrames = m_currentUpdateFrames;
        if (m_audioClient && SUCCEEDED(m_audioClient->GetCurrentPadding(&padding))) {
            UINT32 canWrite = (m_bufferFrameCount > padding) ? (m_bufferFrameCount - padding) : 0;
            if (availFrames > canWrite) {
                availFrames = canWrite;
            }
        }

        if (availFrames > 0 && m_renderClient && m_mixFormat) {
            BYTE* pData = nullptr;
            HRESULT hr = m_renderClient->GetBuffer(availFrames, &pData);
            if (SUCCEEDED(hr) && pData) {
                UINT32 channels = m_mixFormat->nChannels;
                bool isFloat = (m_mixFormat->wFormatTag == WAVE_FORMAT_IEEE_FLOAT);
                if (m_mixFormat->wFormatTag == WAVE_FORMAT_EXTENSIBLE && m_mixFormat->cbSize >= 22) {
                    WAVEFORMATEXTENSIBLE* wfx = reinterpret_cast<WAVEFORMATEXTENSIBLE*>(m_mixFormat);
                    if (wfx->SubFormat == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT) {
                        isFloat = true;
                    }
                }

                if (isFloat && channels >= 2) {
                    float* outFloat = reinterpret_cast<float*>(pData);
                    memset(outFloat, 0, availFrames * channels * sizeof(float));

                    for (size_t i = 0; i < m_objects.size(); ++i) {
                        FakeSpatialAudioObject* obj = m_objects[i];
                        if (!obj->m_isActive || obj->m_validFrames == 0) continue;

                        float gainL = 0.0f, gainR = 0.0f;
                        ComputeStereoGains(obj, gainL, gainR);

                        UINT32 framesToMix = (obj->m_validFrames < availFrames)
                            ? obj->m_validFrames : availFrames;
                        const float* inBuf = obj->m_buffer.data();

                        for (UINT32 f = 0; f < framesToMix; ++f) {
                            float sample = inBuf[f];
                            outFloat[f * channels + 0] += sample * gainL;
                            outFloat[f * channels + 1] += sample * gainR;
                        }
                    }

                    UINT32 totalSamples = availFrames * channels;
                    for (UINT32 s = 0; s < totalSamples; ++s) {
                        if (outFloat[s] > 1.0f) outFloat[s] = 1.0f;
                        else if (outFloat[s] < -1.0f) outFloat[s] = -1.0f;
                    }
                } else if (m_mixFormat->wBitsPerSample == 16 && channels >= 2) {
                    short* outPcm = reinterpret_cast<short*>(pData);
                    memset(outPcm, 0, availFrames * channels * sizeof(short));

                    for (UINT32 f = 0; f < availFrames; ++f) {
                        float sumL = 0.0f, sumR = 0.0f;
                        for (size_t i = 0; i < m_objects.size(); ++i) {
                            FakeSpatialAudioObject* obj = m_objects[i];
                            if (!obj->m_isActive || f >= obj->m_validFrames) continue;
                            float gainL = 0.0f, gainR = 0.0f;
                            ComputeStereoGains(obj, gainL, gainR);
                            float sample = obj->m_buffer[f];
                            sumL += sample * gainL;
                            sumR += sample * gainR;
                        }
                        if (sumL > 1.0f) sumL = 1.0f; else if (sumL < -1.0f) sumL = -1.0f;
                        if (sumR > 1.0f) sumR = 1.0f; else if (sumR < -1.0f) sumR = -1.0f;
                        outPcm[f * channels + 0] = static_cast<short>(sumL * 32767.0f);
                        outPcm[f * channels + 1] = static_cast<short>(sumR * 32767.0f);
                    }
                } else {
                    memset(pData, 0, availFrames * m_mixFormat->nBlockAlign);
                }

                m_renderClient->ReleaseBuffer(availFrames, 0);
            }
        }

        for (size_t i = 0; i < m_objects.size(); ++i) {
            if (m_objects[i]->m_endOfStream) {
                m_objects[i]->m_isActive = FALSE;
                m_objects[i]->m_endOfStream = FALSE;
            }
        }

        LeaveCriticalSection(&m_lock);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ActivateSpatialAudioObject(
        AudioObjectType type,
        ISpatialAudioObject** audioObject) override
    {
        if (!audioObject) return E_POINTER;
        EnterCriticalSection(&m_lock);

        if (!m_loggedFirstObject) {
            m_loggedFirstObject = true;
            LogMsg("[Stream] First ActivateSpatialAudioObject(type=0x%X)", (unsigned)type);
        }

        if (type == AudioObjectType_Dynamic) {
            for (size_t i = 0; i < m_objects.size(); ++i) {
                if (!m_objects[i]->m_isActive && m_objects[i]->m_type == AudioObjectType_Dynamic) {
                    FakeSpatialAudioObject* obj = m_objects[i];
                    obj->m_isActive = TRUE;
                    obj->m_endOfStream = FALSE;
                    obj->m_validFrames = m_currentUpdateFrames ? m_currentUpdateFrames : m_periodFrames;
                    obj->m_x = 0.0f; obj->m_y = 0.0f; obj->m_z = 0.0f;
                    obj->m_volume = 1.0f;
                    obj->AddRef();
                    *audioObject = obj;
                    LeaveCriticalSection(&m_lock);
                    return S_OK;
                }
            }
        }

        FakeSpatialAudioObject* obj = new FakeSpatialAudioObject(type, m_bufferFrameCount ? m_bufferFrameCount : 4096);
        obj->m_validFrames = m_currentUpdateFrames ? m_currentUpdateFrames : m_periodFrames;
        obj->AddRef();
        m_objects.push_back(obj);
        *audioObject = obj;

        LeaveCriticalSection(&m_lock);
        return S_OK;
    }
};

class FakeSpatialAudioClient : public ISpatialAudioClient {
    LONG m_refCount;
    IMMDevice* m_device;
    UINT32 m_nativeSampleRate;
    UINT32 m_periodFrames;

    HRESULT ActivateRawAudioClient(IAudioClient** ppAudioClient) {
        if (!m_device || !ppAudioClient) return E_POINTER;
        return CallRealDeviceActivate(m_device, IID_IAudioClient_Win7, CLSCTX_ALL, nullptr, reinterpret_cast<void**>(ppAudioClient));
    }

public:
    FakeSpatialAudioClient(IMMDevice* device)
        : m_refCount(1), m_device(device), m_nativeSampleRate(48000), m_periodFrames(480)
    {
        if (m_device) {
            m_device->AddRef();
            IAudioClient* tempClient = nullptr;
            HRESULT hr = ActivateRawAudioClient(&tempClient);
            if (SUCCEEDED(hr) && tempClient) {
                WAVEFORMATEX* mixFmt = nullptr;
                if (SUCCEEDED(tempClient->GetMixFormat(&mixFmt)) && mixFmt) {
                    if (mixFmt->nSamplesPerSec > 0) {
                        m_nativeSampleRate = mixFmt->nSamplesPerSec;
                        m_periodFrames = m_nativeSampleRate / 100;
                    }
                    CoTaskMemFree(mixFmt);
                }
                tempClient->Release();
            } else {
                LogMsg("[SpatialAudioClient] Note: ActivateRawAudioClient in ctor returned 0x%08X (using default 48kHz)", (unsigned)hr);
            }
        }
        LogMsg("[SpatialAudioClient] Created %p (Native Sample Rate: %u Hz, Period: %u frames)",
               this, m_nativeSampleRate, m_periodFrames);
    }

    virtual ~FakeSpatialAudioClient() {
        LogMsg("[SpatialAudioClient] ~FakeSpatialAudioClient() destroying %p", this);
        if (m_device) m_device->Release();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown ||
            riid == IID_ISpatialAudioClient_U4 ||
            riid == IID_ISpatialAudioClient_SDK) {
            *ppvObject = static_cast<ISpatialAudioClient*>(this);
            AddRef();
            return S_OK;
        }
        LogMsg("[SpatialAudioClient] QueryInterface for unknown IID Data1=0x%08X", (unsigned)riid.Data1);
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) delete this;
        return ref;
    }

    HRESULT STDMETHODCALLTYPE GetStaticObjectPosition(AudioObjectType type, float* x, float* y, float* z) override {
        if (!x || !y || !z) return E_POINTER;
        *x = 0.0f; *y = 0.0f; *z = 0.0f;
        switch (type) {
            case AudioObjectType_FrontLeft:   *x = -1.0f; *z =  1.0f; break;
            case AudioObjectType_FrontRight:  *x =  1.0f; *z =  1.0f; break;
            case AudioObjectType_FrontCenter: *x =  0.0f; *z =  1.0f; break;
            case AudioObjectType_SideLeft:    *x = -1.0f; *z =  0.0f; break;
            case AudioObjectType_SideRight:   *x =  1.0f; *z =  0.0f; break;
            case AudioObjectType_BackLeft:    *x = -1.0f; *z = -1.0f; break;
            case AudioObjectType_BackRight:   *x =  1.0f; *z = -1.0f; break;
            default: break;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetNativeStaticObjectTypeMask(AudioObjectType* mask) override {
        if (!mask) return E_POINTER;
        *mask = static_cast<AudioObjectType>(
            AudioObjectType_FrontLeft |
            AudioObjectType_FrontRight |
            AudioObjectType_FrontCenter |
            AudioObjectType_LowFrequency |
            AudioObjectType_BackLeft |
            AudioObjectType_BackRight |
            AudioObjectType_SideLeft |
            AudioObjectType_SideRight);
        LogMsg("[SpatialAudioClient] GetNativeStaticObjectTypeMask() -> 0x%X", (unsigned)*mask);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetMaxDynamicObjectCount(UINT32* value) override {
        if (!value) return E_POINTER;
        *value = 128;
        LogMsg("[SpatialAudioClient] GetMaxDynamicObjectCount() -> 128");
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetSupportedAudioObjectFormatEnumerator(IAudioFormatEnumerator** enumerator) override {
        if (!enumerator) return E_POINTER;
        *enumerator = new FakeAudioFormatEnumerator(m_nativeSampleRate);
        LogMsg("[SpatialAudioClient] GetSupportedAudioObjectFormatEnumerator() -> S_OK");
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetMaxFrameCount(const WAVEFORMATEX* objectFormat, UINT32* frameCountPerBuffer) override {
        if (!frameCountPerBuffer) return E_POINTER;
        if (objectFormat && objectFormat->nSamplesPerSec > 0) {
            *frameCountPerBuffer = objectFormat->nSamplesPerSec / 100;
        } else {
            *frameCountPerBuffer = m_periodFrames;
        }
        LogMsg("[SpatialAudioClient] GetMaxFrameCount() -> %u", *frameCountPerBuffer);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE IsAudioObjectFormatSupported(const WAVEFORMATEX* objectFormat) override {
        if (!objectFormat) return E_POINTER;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE IsSpatialAudioStreamAvailable(REFIID streamUuid, const PROPVARIANT* auxiliaryInfo) override {
        LogMsg("[SpatialAudioClient] IsSpatialAudioStreamAvailable(Data1=0x%08X) -> S_OK", (unsigned)streamUuid.Data1);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE ActivateSpatialAudioStream(
        const PROPVARIANT* activationParams,
        REFIID riid,
        void** stream) override
    {
        if (!stream) return E_POINTER;
        *stream = nullptr;

        LogMsg("[SpatialAudioClient] ActivateSpatialAudioStream() called");

        HANDLE gameEvent = nullptr;
        UINT32 maxDynObjects = 128;

        if (activationParams && activationParams->vt == VT_BLOB &&
            activationParams->blob.pBlobData &&
            activationParams->blob.cbSize >= sizeof(SpatialAudioObjectRenderStreamActivationParams_Aligned))
        {
            const SpatialAudioObjectRenderStreamActivationParams_Aligned* params =
                reinterpret_cast<const SpatialAudioObjectRenderStreamActivationParams_Aligned*>(activationParams->blob.pBlobData);
            gameEvent = params->EventHandle;
            if (params->MaxDynamicObjectCount > 0) {
                maxDynObjects = params->MaxDynamicObjectCount;
            }
            LogMsg("[SpatialAudioClient] ActivationParams: cbSize=%u, StaticMask=0x%X, MaxDynamic=%u, EventHandle=%p, NotifyObj=%p",
                   (unsigned)activationParams->blob.cbSize,
                   (unsigned)params->StaticObjectTypeMask,
                   maxDynObjects,
                   gameEvent,
                   params->NotifyObject);
        }

        if (!m_device) return E_FAIL;

        IAudioClient* audioClient = nullptr;
        HRESULT hr = ActivateRawAudioClient(&audioClient);
        if (FAILED(hr) || !audioClient) {
            LogMsg("[SpatialAudioClient] ERROR: ActivateRawAudioClient failed: 0x%08X", (unsigned)hr);
            return hr;
        }

        WAVEFORMATEX* mixFormat = nullptr;
        hr = audioClient->GetMixFormat(&mixFormat);
        if (FAILED(hr) || !mixFormat) {
            LogMsg("[SpatialAudioClient] ERROR: GetMixFormat failed: 0x%08X", (unsigned)hr);
            audioClient->Release();
            return hr;
        }

        DWORD initFlags = gameEvent ? AUDCLNT_STREAMFLAGS_EVENTCALLBACK : 0;
        REFERENCE_TIME hnsBufferDuration = 300000; // 30ms buffer

        hr = audioClient->Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            initFlags,
            hnsBufferDuration,
            0,
            mixFormat,
            nullptr);

        if (FAILED(hr) && initFlags != 0) {
            LogMsg("[SpatialAudioClient] Event-driven init failed (0x%08X), retrying polling mode", (unsigned)hr);
            initFlags = 0;
            hr = audioClient->Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                0,
                hnsBufferDuration,
                0,
                mixFormat,
                nullptr);
        }

        if (FAILED(hr)) {
            LogMsg("[SpatialAudioClient] ERROR: audioClient->Initialize failed: 0x%08X", (unsigned)hr);
            CoTaskMemFree(mixFormat);
            audioClient->Release();
            return hr;
        }

        if ((initFlags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK) && gameEvent) {
            audioClient->SetEventHandle(gameEvent);
        }

        UINT32 bufferFrameCount = 0;
        audioClient->GetBufferSize(&bufferFrameCount);

        REFERENCE_TIME defaultPeriod = 0, minPeriod = 0;
        UINT32 periodFrames = mixFormat->nSamplesPerSec / 100;
        if (SUCCEEDED(audioClient->GetDevicePeriod(&defaultPeriod, &minPeriod)) && defaultPeriod > 0) {
            periodFrames = static_cast<UINT32>((defaultPeriod * mixFormat->nSamplesPerSec) / 10000000ULL);
        }
        if (periodFrames == 0) periodFrames = 480;

        IAudioRenderClient* renderClient = nullptr;
        hr = audioClient->GetService(IID_IAudioRenderClient_Win7, reinterpret_cast<void**>(&renderClient));
        if (FAILED(hr) || !renderClient) {
            LogMsg("[SpatialAudioClient] ERROR: GetService(IAudioRenderClient) failed: 0x%08X", (unsigned)hr);
            CoTaskMemFree(mixFormat);
            audioClient->Release();
            return hr;
        }

        FakeSpatialAudioObjectRenderStream* fakeStream = new FakeSpatialAudioObjectRenderStream(
            audioClient,
            renderClient,
            mixFormat,
            bufferFrameCount,
            periodFrames,
            maxDynObjects,
            gameEvent);

        renderClient->Release();
        audioClient->Release();

        hr = fakeStream->QueryInterface(riid, stream);
        fakeStream->Release();

        LogMsg("[SpatialAudioClient] ActivateSpatialAudioStream() succeeded! Stream=%p, Buffer=%u, Period=%u",
               *stream, bufferFrameCount, periodFrames);
        return hr;
    }
};

// ============================================================================
// 7. COM VTABLE & IAT HOOKS (PER-VTABLE SAFE HOOKS)
// ============================================================================

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint)(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, ERole role, IMMDevice** ppEndpoint);

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceEnumerator_GetDevice)(
    IMMDeviceEnumerator* This, LPCWSTR pwstrId, IMMDevice** ppDevice);

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceCollection_Item)(
    IMMDeviceCollection* This, UINT nDevice, IMMDevice** ppDevice);

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceEnumerator_EnumAudioEndpoints)(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, DWORD dwStateMask, IMMDeviceCollection** ppDevices);

static PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint g_FallbackGetDefaultAudioEndpoint = nullptr;
static PFN_IMMDeviceEnumerator_GetDevice g_FallbackGetDevice = nullptr;
static PFN_IMMDeviceCollection_Item g_FallbackCollectionItem = nullptr;
static PFN_IMMDeviceEnumerator_EnumAudioEndpoints g_FallbackEnumAudioEndpoints = nullptr;

static HRESULT STDMETHODCALLTYPE Hook_IMMDevice_Activate(
    IMMDevice* This,
    REFIID iid,
    DWORD dwClsCtx,
    PROPVARIANT* pActivationParams,
    void** ppInterface)
{
    if (tls_BypassActivateHook) {
        PFN_IMMDevice_Activate origFn = reinterpret_cast<PFN_IMMDevice_Activate>(
            GetOrigVtableSlot(This, 3, reinterpret_cast<void*>(g_FallbackActivate)));
        return origFn ? origFn(This, iid, dwClsCtx, pActivationParams, ppInterface) : E_FAIL;
    }

    // 1. Intercept Windows 10 ISpatialAudioClient
    if (iid == IID_ISpatialAudioClient_U4 || iid == IID_ISpatialAudioClient_SDK) {
        LogMsg("[Hook] Intercepted IMMDevice::Activate(This=%p) for IID_ISpatialAudioClient!", This);
        if (!ppInterface) return E_POINTER;
        *ppInterface = static_cast<ISpatialAudioClient*>(new FakeSpatialAudioClient(This));
        return S_OK;
    }

    // 2. Intercept IAudioClient / IAudioClient2 / IAudioClient3
    if (iid == IID_IAudioClient_Win7 || iid == IID_IAudioClient2_Win8 || iid == IID_IAudioClient3_Win10) {
        LogMsg("[Hook] Intercepted IMMDevice::Activate(This=%p) for IAudioClient/2/3 (Data1=0x%08X)", This, (unsigned)iid.Data1);
        if (!ppInterface) return E_POINTER;
        IAudioClient* realClient = nullptr;
        HRESULT hr = CallRealDeviceActivate(This, IID_IAudioClient_Win7, dwClsCtx, pActivationParams, reinterpret_cast<void**>(&realClient));
        if (SUCCEEDED(hr) && realClient) {
            FakeAudioClient23* wrapper = new FakeAudioClient23(realClient);
            realClient->Release();
            hr = wrapper->QueryInterface(iid, ppInterface);
            wrapper->Release();
            LogMsg("[Hook] Wrapped Win7 IAudioClient into FakeAudioClient23 -> 0x%08X", (unsigned)hr);
            return hr;
        }
        LogMsg("[Hook] ERROR: Underlying Win7 IAudioClient Activate failed -> 0x%08X", (unsigned)hr);
        return hr;
    }

    LogMsg("[Hook] Pass-through IMMDevice::Activate(This=%p, IID Data1=0x%08X)", This, (unsigned)iid.Data1);
    return CallRealDeviceActivate(This, iid, dwClsCtx, pActivationParams, ppInterface);
}

static void HookDeviceVtable(IMMDevice* pDevice) {
    if (!pDevice) return;
    void** vtable = *reinterpret_cast<void***>(pDevice);
    if (!vtable) return;

    EnterCriticalSection(&g_HookLock);
    VtableHookEntry* entry = GetOrCreateVtableEntry(vtable);
    if (vtable[3] != reinterpret_cast<void*>(&Hook_IMMDevice_Activate)) {
        DWORD oldProtect = 0;
        if (VirtualProtect(&vtable[3], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (entry && !entry->origSlot3) {
                entry->origSlot3 = vtable[3];
            }
            if (!g_FallbackActivate) {
                g_FallbackActivate = reinterpret_cast<PFN_IMMDevice_Activate>(vtable[3]);
            }
            vtable[3] = reinterpret_cast<void*>(&Hook_IMMDevice_Activate);
            VirtualProtect(&vtable[3], sizeof(void*), oldProtect, &oldProtect);
            LogMsg("[Hook] Hooked IMMDevice::Activate at vtable %p (orig=%p)",
                   vtable, entry ? entry->origSlot3 : nullptr);
        }
    }
    LeaveCriticalSection(&g_HookLock);
}

static HRESULT STDMETHODCALLTYPE Hook_IMMDeviceCollection_Item(
    IMMDeviceCollection* This, UINT nDevice, IMMDevice** ppDevice)
{
    PFN_IMMDeviceCollection_Item origFn = reinterpret_cast<PFN_IMMDeviceCollection_Item>(
        GetOrigVtableSlot(This, 4, reinterpret_cast<void*>(g_FallbackCollectionItem)));
    HRESULT hr = origFn ? origFn(This, nDevice, ppDevice) : E_FAIL;
    if (SUCCEEDED(hr) && ppDevice && *ppDevice) {
        HookDeviceVtable(*ppDevice);
    }
    return hr;
}

static void HookDeviceCollectionVtable(IMMDeviceCollection* pCollection) {
    if (!pCollection) return;
    void** vtable = *reinterpret_cast<void***>(pCollection);
    if (!vtable) return;

    EnterCriticalSection(&g_HookLock);
    VtableHookEntry* entry = GetOrCreateVtableEntry(vtable);
    if (vtable[4] != reinterpret_cast<void*>(&Hook_IMMDeviceCollection_Item)) {
        DWORD oldProtect = 0;
        if (VirtualProtect(&vtable[4], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (entry && !entry->origSlot4) {
                entry->origSlot4 = vtable[4];
            }
            if (!g_FallbackCollectionItem) {
                g_FallbackCollectionItem = reinterpret_cast<PFN_IMMDeviceCollection_Item>(vtable[4]);
            }
            vtable[4] = reinterpret_cast<void*>(&Hook_IMMDeviceCollection_Item);
            VirtualProtect(&vtable[4], sizeof(void*), oldProtect, &oldProtect);
        }
    }
    LeaveCriticalSection(&g_HookLock);
}

static HRESULT STDMETHODCALLTYPE Hook_EnumAudioEndpoints(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, DWORD dwStateMask, IMMDeviceCollection** ppDevices)
{
    PFN_IMMDeviceEnumerator_EnumAudioEndpoints origFn = reinterpret_cast<PFN_IMMDeviceEnumerator_EnumAudioEndpoints>(
        GetOrigVtableSlot(This, 3, reinterpret_cast<void*>(g_FallbackEnumAudioEndpoints)));
    HRESULT hr = origFn ? origFn(This, dataFlow, dwStateMask, ppDevices) : E_FAIL;
    if (SUCCEEDED(hr) && ppDevices && *ppDevices) {
        HookDeviceCollectionVtable(*ppDevices);
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE Hook_GetDefaultAudioEndpoint(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, ERole role, IMMDevice** ppEndpoint)
{
    PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint origFn = reinterpret_cast<PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint>(
        GetOrigVtableSlot(This, 4, reinterpret_cast<void*>(g_FallbackGetDefaultAudioEndpoint)));
    HRESULT hr = origFn ? origFn(This, dataFlow, role, ppEndpoint) : E_FAIL;
    if (SUCCEEDED(hr) && ppEndpoint && *ppEndpoint) {
        HookDeviceVtable(*ppEndpoint);
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE Hook_GetDevice(
    IMMDeviceEnumerator* This, LPCWSTR pwstrId, IMMDevice** ppDevice)
{
    PFN_IMMDeviceEnumerator_GetDevice origFn = reinterpret_cast<PFN_IMMDeviceEnumerator_GetDevice>(
        GetOrigVtableSlot(This, 5, reinterpret_cast<void*>(g_FallbackGetDevice)));
    HRESULT hr = origFn ? origFn(This, pwstrId, ppDevice) : E_FAIL;
    if (SUCCEEDED(hr) && ppDevice && *ppDevice) {
        HookDeviceVtable(*ppDevice);
    }
    return hr;
}

static void HookEnumeratorVtable(IMMDeviceEnumerator* pEnum) {
    if (!pEnum) return;
    void** vtable = *reinterpret_cast<void***>(pEnum);
    if (!vtable) return;

    EnterCriticalSection(&g_HookLock);
    VtableHookEntry* entry = GetOrCreateVtableEntry(vtable);
    DWORD oldProtect = 0;
    if (VirtualProtect(&vtable[3], sizeof(void*) * 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        if (vtable[3] != reinterpret_cast<void*>(&Hook_EnumAudioEndpoints)) {
            if (entry && !entry->origSlot3) entry->origSlot3 = vtable[3];
            if (!g_FallbackEnumAudioEndpoints)
                g_FallbackEnumAudioEndpoints = reinterpret_cast<PFN_IMMDeviceEnumerator_EnumAudioEndpoints>(vtable[3]);
            vtable[3] = reinterpret_cast<void*>(&Hook_EnumAudioEndpoints);
        }
        if (vtable[4] != reinterpret_cast<void*>(&Hook_GetDefaultAudioEndpoint)) {
            if (entry && !entry->origSlot4) entry->origSlot4 = vtable[4];
            if (!g_FallbackGetDefaultAudioEndpoint)
                g_FallbackGetDefaultAudioEndpoint = reinterpret_cast<PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint>(vtable[4]);
            vtable[4] = reinterpret_cast<void*>(&Hook_GetDefaultAudioEndpoint);
        }
        if (vtable[5] != reinterpret_cast<void*>(&Hook_GetDevice)) {
            if (entry && !entry->origSlot5) entry->origSlot5 = vtable[5];
            if (!g_FallbackGetDevice)
                g_FallbackGetDevice = reinterpret_cast<PFN_IMMDeviceEnumerator_GetDevice>(vtable[5]);
            vtable[5] = reinterpret_cast<void*>(&Hook_GetDevice);
        }
        VirtualProtect(&vtable[3], sizeof(void*) * 3, oldProtect, &oldProtect);
    }
    LeaveCriticalSection(&g_HookLock);
}

typedef HRESULT (WINAPI *PFN_CoCreateInstance)(
    REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);

static PFN_CoCreateInstance g_OrigCoCreateInstance = nullptr;

static HRESULT WINAPI Hook_CoCreateInstance(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID* ppv)
{
    HRESULT hr = g_OrigCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    if (SUCCEEDED(hr) && rclsid == CLSID_MMDeviceEnumerator_Win7 && ppv && *ppv) {
        IMMDeviceEnumerator* pEnum = nullptr;
        if (SUCCEEDED(static_cast<IUnknown*>(*ppv)->QueryInterface(IID_IMMDeviceEnumerator_Win7, reinterpret_cast<void**>(&pEnum))) && pEnum) {
            HookEnumeratorVtable(pEnum);
            pEnum->Release();
        }
    }
    return hr;
}

static void PatchModuleIAT(HMODULE hMod, const char* funcName, void* newFunc, void** oldFuncOut) {
    if (!hMod) return;
    BYTE* base = reinterpret_cast<BYTE*>(hMod);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRVA) return;

    IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importRVA);
    for (; importDesc->Name; ++importDesc) {
        if (!importDesc->OriginalFirstThunk || !importDesc->FirstThunk) continue;

        IMAGE_THUNK_DATA* origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* iatThunk  = reinterpret_cast<IMAGE_THUNK_DATA*>(base + importDesc->FirstThunk);

        for (; origThunk->u1.AddressOfData; ++origThunk, ++iatThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
            if (strcmp(reinterpret_cast<const char*>(importByName->Name), funcName) == 0) {
                DWORD oldProtect = 0;
                if (VirtualProtect(&iatThunk->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect)) {
                    if (oldFuncOut && !*oldFuncOut) {
                        *oldFuncOut = reinterpret_cast<void*>(iatThunk->u1.Function);
                    }
                    iatThunk->u1.Function = reinterpret_cast<ULONG_PTR>(newFunc);
                    VirtualProtect(&iatThunk->u1.Function, sizeof(ULONG_PTR), oldProtect, &oldProtect);
                    LogMsg("[Hook] Patched IAT for %s in module %p", funcName, hMod);
                }
            }
        }
    }
}

static void InstallCoCreateInstanceHooks() {
    HMODULE hOle32 = GetModuleHandleW(L"ole32.dll");
    if (!hOle32) hOle32 = LoadLibraryW(L"ole32.dll");
    if (hOle32) {
        g_OrigCoCreateInstance = reinterpret_cast<PFN_CoCreateInstance>(GetProcAddress(hOle32, "CoCreateInstance"));
    }

    PatchModuleIAT(
        GetModuleHandleW(nullptr),
        "CoCreateInstance",
        reinterpret_cast<void*>(&Hook_CoCreateInstance),
        reinterpret_cast<void**>(&g_OrigCoCreateInstance));
}

// ============================================================================
// 8. REAL VERSION.DLL FORWARDERS
// ============================================================================
static HMODULE g_hRealVersion = nullptr;

static FARPROC GetVersionProc(const char* name) {
    if (!g_hRealVersion) {
        WCHAR sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        wcscat_s(sysDir, MAX_PATH, L"\\version.dll");
        g_hRealVersion = LoadLibraryW(sysDir);
    }
    return g_hRealVersion ? GetProcAddress(g_hRealVersion, name) : nullptr;
}

extern "C" {

BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *PFN)(LPCSTR, DWORD, DWORD, LPVOID);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoA"));
    return fn ? fn(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoByHandle(DWORD dwFlags, HANDLE hFile, LPVOID* lplpData, PDWORD pdwLen) {
    typedef BOOL (WINAPI *PFN)(DWORD, HANDLE, LPVOID*, PDWORD);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoByHandle"));
    return fn ? fn(dwFlags, hFile, lplpData, pdwLen) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *PFN)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoExA"));
    return fn ? fn(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *PFN)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoExW"));
    return fn ? fn(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *PFN)(LPCSTR, LPDWORD);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoSizeA"));
    return fn ? fn(lptstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPCSTR, LPDWORD);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoSizeExA"));
    return fn ? fn(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPCWSTR, LPDWORD);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoSizeExW"));
    return fn ? fn(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *PFN)(LPCWSTR, LPDWORD);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoSizeW"));
    return fn ? fn(lptstrFilename, lpdwHandle) : 0;
}

BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *PFN)(LPCWSTR, DWORD, DWORD, LPVOID);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("GetFileVersionInfoW"));
    return fn ? fn(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

DWORD WINAPI Proxy_VerFindFileA(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir, LPSTR szCurDir, PUINT lpuCurDirLen, LPSTR szDestDir, PUINT lpuDestDirLen) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerFindFileA"));
    return fn ? fn(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen) : 0;
}

DWORD WINAPI Proxy_VerFindFileW(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir, LPWSTR szCurDir, PUINT lpuCurDirLen, LPWSTR szDestDir, PUINT lpuDestDirLen) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerFindFileW"));
    return fn ? fn(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen) : 0;
}

DWORD WINAPI Proxy_VerInstallFileA(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT lpuTmpFileLen) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerInstallFileA"));
    return fn ? fn(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, lpuTmpFileLen) : 0;
}

DWORD WINAPI Proxy_VerInstallFileW(DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName, LPCWSTR szSrcDir, LPCWSTR szDestDir, LPCWSTR szCurDir, LPWSTR szTmpFile, PUINT lpuTmpFileLen) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerInstallFileW"));
    return fn ? fn(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, lpuTmpFileLen) : 0;
}

DWORD WINAPI Proxy_VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPSTR, DWORD);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerLanguageNameA"));
    return fn ? fn(wLang, szLang, cchLang) : 0;
}

DWORD WINAPI Proxy_VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    typedef DWORD (WINAPI *PFN)(DWORD, LPWSTR, DWORD);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerLanguageNameW"));
    return fn ? fn(wLang, szLang, cchLang) : 0;
}

BOOL WINAPI Proxy_VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    typedef BOOL (WINAPI *PFN)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerQueryValueA"));
    return fn ? fn(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

BOOL WINAPI Proxy_VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    typedef BOOL (WINAPI *PFN)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    static PFN fn = reinterpret_cast<PFN>(GetVersionProc("VerQueryValueW"));
    return fn ? fn(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

} // extern "C"

// ============================================================================
// 9. DLL ENTRY POINT
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hSelfModule = hModule;
        DisableThreadLibraryCalls(hModule);
        InitLog();
        AddVectoredExceptionHandler(1, CrashDiagnosticHandler);
        LogMsg("=== Uncharted 4 Win7 SpatialAudio + IAudioClient2/3 Proxy v3 Loaded (Base=%p) ===", hModule);
        InstallCoCreateInstanceHooks();
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        LogMsg("=== Uncharted 4 Win7 Proxy v3 Unloading ===");
    }
    return TRUE;
}