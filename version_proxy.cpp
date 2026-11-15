#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <ks.h>
#include <ksmedia.h>
#include <PropIdl.h>
#include <cmath>
#include <vector>
#include <cstdio>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

// ============================================================================
// 1. LOGGING UTILITY
// ============================================================================
static CRITICAL_SECTION g_LogLock;
static bool g_LogInit = false;

static void LogMsg(const char* fmt, ...) {
    if (!g_LogInit) return;
    EnterCriticalSection(&g_LogLock);
    FILE* f = fopen("u4_spatial_proxy.log", "a");
    if (f) {
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
    LeaveCriticalSection(&g_LogLock);
}

// ============================================================================
// 2. WINDOWS 10 SPATIAL AUDIO GUIDS, ENUMS & STRUCTURES
// ============================================================================
// {DC8E63F3-D12B-4952-B47B-5E45026A862D} - Requested by u4.exe
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

typedef enum AudioObjectType {
    AudioObjectType_None            = 0,
    AudioObjectType_Dynamic         = (1 << 0),
    AudioObjectType_FrontLeft       = (1 << 1),
    AudioObjectType_FrontRight      = (1 << 2),
    AudioObjectType_FrontCenter     = (1 << 3),
    AudioObjectType_LowFrequency    = (1 << 4),
    AudioObjectType_SideLeft        = (1 << 5),
    AudioObjectType_SideRight       = (1 << 6),
    AudioObjectType_BackLeft        = (1 << 7),
    AudioObjectType_BackRight       = (1 << 8),
    AudioObjectType_TopFrontLeft    = (1 << 9),
    AudioObjectType_TopFrontRight   = (1 << 10),
    AudioObjectType_TopBackLeft     = (1 << 11),
    AudioObjectType_TopBackRight    = (1 << 12),
    AudioObjectType_BottomFrontLeft = (1 << 13),
    AudioObjectType_BottomFrontRight= (1 << 14),
    AudioObjectType_BottomBackLeft  = (1 << 15),
    AudioObjectType_BottomBackRight = (1 << 16),
    AudioObjectType_BackCenter      = (1 << 17)
} AudioObjectType;

struct ISpatialAudioObjectRenderStreamNotify : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE OnAvailableDynamicObjectCountChange(
        IUnknown* sender, LONGLONG hnsComplianceDeadlineTime, UINT32 availableDynamicObjectCountChange) = 0;
};

#pragma pack(push, 1)
struct SpatialAudioObjectRenderStreamActivationParams {
    const WAVEFORMATEX* ObjectFormat;
    AudioObjectType StaticObjectTypeMask;
    UINT32 MinDynamicObjectCount;
    UINT32 MaxDynamicObjectCount;
    int Category;
    HANDLE EventHandle;
    ISpatialAudioObjectRenderStreamNotify* NotifyObject;
};

struct SpatialAudioObjectRenderStreamActivationParams2 {
    const WAVEFORMATEX* ObjectFormat;
    AudioObjectType StaticObjectTypeMask;
    UINT32 MinDynamicObjectCount;
    UINT32 MaxDynamicObjectCount;
    int Category;
    HANDLE EventHandle;
    ISpatialAudioObjectRenderStreamNotify* NotifyObject;
    int Options;
};
#pragma pack(pop)

// ============================================================================
// 3. EXACT VTABLE INTERFACES FOR WINDOWS 10 SPATIAL AUDIO
// ============================================================================
struct IAudioFormatEnumerator : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetCount(UINT32* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetFormat(UINT32 index, WAVEFORMATEX** format) = 0;
};

struct ISpatialAudioObject : public IUnknown {
    // ISpatialAudioObjectBase
    virtual HRESULT STDMETHODCALLTYPE GetBuffer(BYTE** buffer, UINT32* bufferLength) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetEndOfStream(UINT32 frameCount) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsActive(BOOL* isActive) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAudioObjectType(AudioObjectType* audioObjectType) = 0;
    // ISpatialAudioObject
    virtual HRESULT STDMETHODCALLTYPE SetPosition(float x, float y, float z) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetVolume(float volume) = 0;
};

struct ISpatialAudioObjectRenderStream : public IUnknown {
    // ISpatialAudioObjectRenderStreamBase
    virtual HRESULT STDMETHODCALLTYPE GetAvailableDynamicObjectCount(UINT32* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetService(REFIID riid, void** service) = 0;
    virtual HRESULT STDMETHODCALLTYPE Start(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Stop(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE Reset(void) = 0;
    virtual HRESULT STDMETHODCALLTYPE BeginUpdatingAudioObjects(UINT32* availableDynamicObjectCount, UINT32* frameCountPerBuffer) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndUpdatingAudioObjects(void) = 0;
    // ISpatialAudioObjectRenderStream
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
// 4. EMULATION IMPLEMENTATIONS (DOWNMIX TO WIN7 WASAPI)
// ============================================================================

class FakeAudioFormatEnumerator : public IAudioFormatEnumerator {
    LONG m_refCount;
    WAVEFORMATEX m_format;
public:
    FakeAudioFormatEnumerator(UINT32 sampleRate) : m_refCount(1) {
        m_format.wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
        m_format.nChannels = 1; // Spatial audio objects are mono float streams
        m_format.nSamplesPerSec = sampleRate ? sampleRate : 48000;
        m_format.wBitsPerSample = 32;
        m_format.nBlockAlign = 4;
        m_format.nAvgBytesPerSec = m_format.nSamplesPerSec * m_format.nBlockAlign;
        m_format.cbSize = 0;
    }

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
          m_volume(1.0f), m_isActive(TRUE), m_endOfStream(FALSE), m_validFrames(0) {
        m_buffer.resize(maxFrames, 0.0f);
    }

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
        if (m_validFrames > m_buffer.size()) {
            m_buffer.resize(m_validFrames, 0.0f);
        }
        memset(m_buffer.data(), 0, m_validFrames * sizeof(float));
        *buffer = reinterpret_cast<BYTE*>(m_buffer.data());
        *bufferLength = m_validFrames * sizeof(float);
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
    bool m_running;

    static DWORD WINAPI PumpThreadProc(LPVOID param) {
        FakeSpatialAudioObjectRenderStream* self = static_cast<FakeSpatialAudioObjectRenderStream*>(param);
        self->PumpLoop();
        return 0;
    }

    void PumpLoop() {
        while (WaitForSingleObject(m_stopEvent, 10) == WAIT_TIMEOUT) {
            if (m_running && m_gameEvent) {
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
                float angle = (pan + 1.0f) * 0.78539816f; // (pan + 1) * (PI / 4)
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
          m_running(false)
    {
        InitializeCriticalSection(&m_lock);
        if (m_audioClient) m_audioClient->AddRef();
        if (m_renderClient) m_renderClient->AddRef();

        // Fallback safety thread in case the game relies on manual event pulsing
        m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        m_pumpThread = CreateThread(nullptr, 0, PumpThreadProc, this, 0, nullptr);
    }

    ~FakeSpatialAudioObjectRenderStream() {
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
        if (!m_audioClient) return E_FAIL;
        return m_audioClient->GetService(riid, service);
    }

    HRESULT STDMETHODCALLTYPE Start(void) override {
        LogMsg("[Stream] Start() called");
        m_running = true;
        if (m_gameEvent) SetEvent(m_gameEvent);
        return m_audioClient ? m_audioClient->Start() : S_OK;
    }

    HRESULT STDMETHODCALLTYPE Stop(void) override {
        LogMsg("[Stream] Stop() called");
        m_running = false;
        return m_audioClient ? m_audioClient->Stop() : S_OK;
    }

    HRESULT STDMETHODCALLTYPE Reset(void) override {
        LogMsg("[Stream] Reset() called");
        return m_audioClient ? m_audioClient->Reset() : S_OK;
    }

    HRESULT STDMETHODCALLTYPE BeginUpdatingAudioObjects(
        UINT32* availableDynamicObjectCount,
        UINT32* frameCountPerBuffer) override
    {
        EnterCriticalSection(&m_lock);

        UINT32 padding = 0;
        if (m_audioClient && SUCCEEDED(m_audioClient->GetCurrentPadding(&padding))) {
            UINT32 avail = (m_bufferFrameCount > padding) ? (m_bufferFrameCount - padding) : 0;
            if (avail == 0) {
                m_currentUpdateFrames = 0;
            } else if (avail > m_periodFrames) {
                m_currentUpdateFrames = m_periodFrames;
            } else {
                m_currentUpdateFrames = avail;
            }
        } else {
            m_currentUpdateFrames = m_periodFrames;
        }

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

        LeaveCriticalSection(&m_lock);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE EndUpdatingAudioObjects(void) override {
        EnterCriticalSection(&m_lock);

        if (m_currentUpdateFrames > 0 && m_renderClient && m_mixFormat) {
            BYTE* pData = nullptr;
            HRESULT hr = m_renderClient->GetBuffer(m_currentUpdateFrames, &pData);
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
                    memset(outFloat, 0, m_currentUpdateFrames * channels * sizeof(float));

                    for (size_t i = 0; i < m_objects.size(); ++i) {
                        FakeSpatialAudioObject* obj = m_objects[i];
                        if (!obj->m_isActive || obj->m_validFrames == 0) continue;

                        float gainL = 0.0f, gainR = 0.0f;
                        ComputeStereoGains(obj, gainL, gainR);

                        UINT32 framesToMix = (obj->m_validFrames < m_currentUpdateFrames)
                            ? obj->m_validFrames : m_currentUpdateFrames;
                        const float* inBuf = obj->m_buffer.data();

                        for (UINT32 f = 0; f < framesToMix; ++f) {
                            float sample = inBuf[f];
                            outFloat[f * channels + 0] += sample * gainL;
                            outFloat[f * channels + 1] += sample * gainR;
                        }
                    }

                    // Soft clip to prevent distortion when many objects sum together
                    UINT32 totalSamples = m_currentUpdateFrames * channels;
                    for (UINT32 s = 0; s < totalSamples; ++s) {
                        if (outFloat[s] > 1.0f) outFloat[s] = 1.0f;
                        else if (outFloat[s] < -1.0f) outFloat[s] = -1.0f;
                    }
                } else if (m_mixFormat->wBitsPerSample == 16 && channels >= 2) {
                    // Fallback 16-bit PCM downmix
                    short* outPcm = reinterpret_cast<short*>(pData);
                    memset(outPcm, 0, m_currentUpdateFrames * channels * sizeof(short));

                    for (UINT32 f = 0; f < m_currentUpdateFrames; ++f) {
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
                    memset(pData, 0, m_currentUpdateFrames * m_mixFormat->nBlockAlign);
                }

                m_renderClient->ReleaseBuffer(m_currentUpdateFrames, 0);
            }
        }

        // Clean up objects marked EndOfStream
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

        FakeSpatialAudioObject* obj = new FakeSpatialAudioObject(type, m_bufferFrameCount ? m_bufferFrameCount : 4096);
        obj->AddRef(); // One ref for internal list, one ref returned to caller
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

public:
    FakeSpatialAudioClient(IMMDevice* device)
        : m_refCount(1), m_device(device), m_nativeSampleRate(48000), m_periodFrames(480)
    {
        if (m_device) {
            m_device->AddRef();
            IAudioClient* tempClient = nullptr;
            if (SUCCEEDED(m_device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&tempClient)) && tempClient) {
                WAVEFORMATEX* mixFmt = nullptr;
                if (SUCCEEDED(tempClient->GetMixFormat(&mixFmt)) && mixFmt) {
                    m_nativeSampleRate = mixFmt->nSamplesPerSec;
                    m_periodFrames = m_nativeSampleRate / 100; // 10ms period
                    CoTaskMemFree(mixFmt);
                }
                tempClient->Release();
            }
        }
        LogMsg("[SpatialAudioClient] Created (Native Sample Rate: %u Hz, Period: %u frames)",
               m_nativeSampleRate, m_periodFrames);
    }

    ~FakeSpatialAudioClient() {
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
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetMaxDynamicObjectCount(UINT32* value) override {
        if (!value) return E_POINTER;
        *value = 128;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetSupportedAudioObjectFormatEnumerator(IAudioFormatEnumerator** enumerator) override {
        if (!enumerator) return E_POINTER;
        *enumerator = new FakeAudioFormatEnumerator(m_nativeSampleRate);
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetMaxFrameCount(const WAVEFORMATEX* objectFormat, UINT32* frameCountPerBuffer) override {
        if (!frameCountPerBuffer) return E_POINTER;
        if (objectFormat && objectFormat->nSamplesPerSec > 0) {
            *frameCountPerBuffer = objectFormat->nSamplesPerSec / 100; // 10ms
        } else {
            *frameCountPerBuffer = m_periodFrames;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE IsAudioObjectFormatSupported(const WAVEFORMATEX* objectFormat) override {
        if (!objectFormat) return E_POINTER;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE IsSpatialAudioStreamAvailable(REFIID streamUuid, const PROPVARIANT* auxiliaryInfo) override {
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
            activationParams->blob.cbSize >= sizeof(SpatialAudioObjectRenderStreamActivationParams))
        {
            const SpatialAudioObjectRenderStreamActivationParams* params =
                reinterpret_cast<const SpatialAudioObjectRenderStreamActivationParams*>(activationParams->blob.pBlobData);
            gameEvent = params->EventHandle;
            if (params->MaxDynamicObjectCount > 0) {
                maxDynObjects = params->MaxDynamicObjectCount;
            }
            LogMsg("[SpatialAudioClient] ActivationParams: MaxDynamic=%u, EventHandle=%p",
                   maxDynObjects, gameEvent);
        }

        if (!m_device) return E_FAIL;

        IAudioClient* audioClient = nullptr;
        HRESULT hr = m_device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, (void**)&audioClient);
        if (FAILED(hr) || !audioClient) {
            LogMsg("[SpatialAudioClient] ERROR: m_device->Activate(IAudioClient) failed: 0x%08X", hr);
            return hr;
        }

        WAVEFORMATEX* mixFormat = nullptr;
        hr = audioClient->GetMixFormat(&mixFormat);
        if (FAILED(hr) || !mixFormat) {
            LogMsg("[SpatialAudioClient] ERROR: GetMixFormat failed: 0x%08X", hr);
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
            LogMsg("[SpatialAudioClient] Event-driven init failed (0x%08X), retrying polling mode", hr);
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
            LogMsg("[SpatialAudioClient] ERROR: audioClient->Initialize failed: 0x%08X", hr);
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
        hr = audioClient->GetService(__uuidof(IAudioRenderClient), (void**)&renderClient);
        if (FAILED(hr) || !renderClient) {
            LogMsg("[SpatialAudioClient] ERROR: GetService(IAudioRenderClient) failed: 0x%08X", hr);
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

        LogMsg("[SpatialAudioClient] ActivateSpatialAudioStream() succeeded! Buffer=%u, Period=%u",
               bufferFrameCount, periodFrames);
        return hr;
    }
};

// ============================================================================
// 5. COM VTABLE & IAT HOOKS (CoCreateInstance -> IMMDeviceEnumerator -> IMMDevice)
// ============================================================================

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDevice_Activate)(
    IMMDevice* This, REFIID iid, DWORD dwClsCtx, PROPVARIANT* pActivationParams, void** ppInterface);

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint)(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, ERole role, IMMDevice** ppEndpoint);

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceEnumerator_GetDevice)(
    IMMDeviceEnumerator* This, LPCWSTR pwstrId, IMMDevice** ppDevice);

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceCollection_Item)(
    IMMDeviceCollection* This, UINT nDevice, IMMDevice** ppDevice);

typedef HRESULT (STDMETHODCALLTYPE *PFN_IMMDeviceEnumerator_EnumAudioEndpoints)(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, DWORD dwStateMask, IMMDeviceCollection** ppDevices);

static PFN_IMMDevice_Activate g_OrigActivate = nullptr;
static PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint g_OrigGetDefaultAudioEndpoint = nullptr;
static PFN_IMMDeviceEnumerator_GetDevice g_OrigGetDevice = nullptr;
static PFN_IMMDeviceCollection_Item g_OrigCollectionItem = nullptr;
static PFN_IMMDeviceEnumerator_EnumAudioEndpoints g_OrigEnumAudioEndpoints = nullptr;

static HRESULT STDMETHODCALLTYPE Hook_IMMDevice_Activate(
    IMMDevice* This,
    REFIID iid,
    DWORD dwClsCtx,
    PROPVARIANT* pActivationParams,
    void** ppInterface)
{
    if (iid == IID_ISpatialAudioClient_U4 || iid == IID_ISpatialAudioClient_SDK) {
        LogMsg("[Hook] Intercepted IMMDevice::Activate for IID_ISpatialAudioClient!");
        if (!ppInterface) return E_POINTER;
        *ppInterface = static_cast<ISpatialAudioClient*>(new FakeSpatialAudioClient(This));
        return S_OK;
    }
    return g_OrigActivate(This, iid, dwClsCtx, pActivationParams, ppInterface);
}

static void HookDeviceVtable(IMMDevice* pDevice) {
    if (!pDevice) return;
    void** vtable = *reinterpret_cast<void***>(pDevice);
    if (!vtable) return;

    // IMMDevice::Activate is vtable index 3
    if (vtable[3] != reinterpret_cast<void*>(&Hook_IMMDevice_Activate)) {
        DWORD oldProtect = 0;
        if (VirtualProtect(&vtable[3], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (!g_OrigActivate) {
                g_OrigActivate = reinterpret_cast<PFN_IMMDevice_Activate>(vtable[3]);
            }
            vtable[3] = reinterpret_cast<void*>(&Hook_IMMDevice_Activate);
            VirtualProtect(&vtable[3], sizeof(void*), oldProtect, &oldProtect);
            LogMsg("[Hook] Hooked IMMDevice::Activate at vtable[3]");
        }
    }
}

static HRESULT STDMETHODCALLTYPE Hook_IMMDeviceCollection_Item(
    IMMDeviceCollection* This, UINT nDevice, IMMDevice** ppDevice)
{
    HRESULT hr = g_OrigCollectionItem(This, nDevice, ppDevice);
    if (SUCCEEDED(hr) && ppDevice && *ppDevice) {
        HookDeviceVtable(*ppDevice);
    }
    return hr;
}

static void HookDeviceCollectionVtable(IMMDeviceCollection* pCollection) {
    if (!pCollection) return;
    void** vtable = *reinterpret_cast<void***>(pCollection);
    if (!vtable) return;

    // IMMDeviceCollection::Item is vtable index 4
    if (vtable[4] != reinterpret_cast<void*>(&Hook_IMMDeviceCollection_Item)) {
        DWORD oldProtect = 0;
        if (VirtualProtect(&vtable[4], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (!g_OrigCollectionItem) {
                g_OrigCollectionItem = reinterpret_cast<PFN_IMMDeviceCollection_Item>(vtable[4]);
            }
            vtable[4] = reinterpret_cast<void*>(&Hook_IMMDeviceCollection_Item);
            VirtualProtect(&vtable[4], sizeof(void*), oldProtect, &oldProtect);
        }
    }
}

static HRESULT STDMETHODCALLTYPE Hook_EnumAudioEndpoints(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, DWORD dwStateMask, IMMDeviceCollection** ppDevices)
{
    HRESULT hr = g_OrigEnumAudioEndpoints(This, dataFlow, dwStateMask, ppDevices);
    if (SUCCEEDED(hr) && ppDevices && *ppDevices) {
        HookDeviceCollectionVtable(*ppDevices);
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE Hook_GetDefaultAudioEndpoint(
    IMMDeviceEnumerator* This, EDataFlow dataFlow, ERole role, IMMDevice** ppEndpoint)
{
    HRESULT hr = g_OrigGetDefaultAudioEndpoint(This, dataFlow, role, ppEndpoint);
    if (SUCCEEDED(hr) && ppEndpoint && *ppEndpoint) {
        HookDeviceVtable(*ppEndpoint);
    }
    return hr;
}

static HRESULT STDMETHODCALLTYPE Hook_GetDevice(
    IMMDeviceEnumerator* This, LPCWSTR pwstrId, IMMDevice** ppDevice)
{
    HRESULT hr = g_OrigGetDevice(This, pwstrId, ppDevice);
    if (SUCCEEDED(hr) && ppDevice && *ppDevice) {
        HookDeviceVtable(*ppDevice);
    }
    return hr;
}

static void HookEnumeratorVtable(IMMDeviceEnumerator* pEnum) {
    if (!pEnum) return;
    void** vtable = *reinterpret_cast<void***>(pEnum);
    if (!vtable) return;

    DWORD oldProtect = 0;
    if (VirtualProtect(&vtable[3], sizeof(void*) * 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // vtable[3]: EnumAudioEndpoints
        if (vtable[3] != reinterpret_cast<void*>(&Hook_EnumAudioEndpoints)) {
            if (!g_OrigEnumAudioEndpoints)
                g_OrigEnumAudioEndpoints = reinterpret_cast<PFN_IMMDeviceEnumerator_EnumAudioEndpoints>(vtable[3]);
            vtable[3] = reinterpret_cast<void*>(&Hook_EnumAudioEndpoints);
        }
        // vtable[4]: GetDefaultAudioEndpoint
        if (vtable[4] != reinterpret_cast<void*>(&Hook_GetDefaultAudioEndpoint)) {
            if (!g_OrigGetDefaultAudioEndpoint)
                g_OrigGetDefaultAudioEndpoint = reinterpret_cast<PFN_IMMDeviceEnumerator_GetDefaultAudioEndpoint>(vtable[4]);
            vtable[4] = reinterpret_cast<void*>(&Hook_GetDefaultAudioEndpoint);
        }
        // vtable[5]: GetDevice
        if (vtable[5] != reinterpret_cast<void*>(&Hook_GetDevice)) {
            if (!g_OrigGetDevice)
                g_OrigGetDevice = reinterpret_cast<PFN_IMMDeviceEnumerator_GetDevice>(vtable[5]);
            vtable[5] = reinterpret_cast<void*>(&Hook_GetDevice);
        }
        VirtualProtect(&vtable[3], sizeof(void*) * 3, oldProtect, &oldProtect);
        LogMsg("[Hook] Hooked IMMDeviceEnumerator vtable");
    }
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
    if (SUCCEEDED(hr) && rclsid == __uuidof(MMDeviceEnumerator) && ppv && *ppv) {
        LogMsg("[Hook] CoCreateInstance(CLSID_MMDeviceEnumerator) intercepted");
        IMMDeviceEnumerator* pEnum = nullptr;
        if (SUCCEEDED(static_cast<IUnknown*>(*ppv)->QueryInterface(__uuidof(IMMDeviceEnumerator), (void**)&pEnum)) && pEnum) {
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

    // Patch main executable (u4.exe) synchronously before WinMain starts
    PatchModuleIAT(GetModuleHandleW(nullptr), "CoCreateInstance", reinterpret_cast<void*>(&Hook_CoCreateInstance), reinterpret_cast<void**>(&g_OrigCoCreateInstance));
}

// ============================================================================
// 6. REAL VERSION.DLL FORWARDERS
// ============================================================================
static HMODULE g_hRealVersion = nullptr;

static FARPROC GetVersionProc(const char* name) {
    if (!g_hRealVersion) {
        WCHAR sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        wcscat_s(sysDir, L"\\version.dll");
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
// 7. DLL ENTRY POINT
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_LogLock);
        g_LogInit = true;
        DeleteFileA("u4_spatial_proxy.log");
        LogMsg("=== Uncharted 4 Win7 SpatialAudio Proxy Loaded ===");
        InstallCoCreateInstanceHooks();
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (g_hRealVersion) {
            FreeLibrary(g_hRealVersion);
            g_hRealVersion = nullptr;
        }
        if (g_LogInit) {
            g_LogInit = false;
            DeleteCriticalSection(&g_LogLock);
        }
    }
    return TRUE;
}