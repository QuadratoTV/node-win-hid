#ifdef _WIN32

#define NOMINMAX
#include "WinHID.h"

#include <setupapi.h>
#include <hidsdi.h>
#include <hidusage.h>
#include <initguid.h>
#include <devpkey.h>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <algorithm>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "cfgmgr32.lib")

// ---------- debug ----------
static bool g_debug_inited = false;
static bool g_debug = false;

static void dbg_init() {
  if (g_debug_inited) return;
  g_debug_inited = true;
  const char* e = getenv("WINHID_DEBUG");
  g_debug = (e && *e && e[0] != '0');
}

static void dbg_printf(const char* fmt, ...) {
  dbg_init();
  if (!g_debug) return;
  char buf[2048];
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
  va_end(ap);
  fputs(buf, stderr);
  fputc('\n', stderr);
  OutputDebugStringA(buf);
  OutputDebugStringA("\n");
}

// ---------- helpers ----------
static std::string wstr_to_utf8(const wchar_t* w) {
  if (!w) return {};
  int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
  if (len <= 0) return {};
  std::string s(len - 1, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
  return s;
}
static std::string wstr_to_utf8(const std::wstring& w) { return wstr_to_utf8(w.c_str()); }

static std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c){ return (char)std::tolower(c); });
  return s;
}

static std::string normalize_path_u8(const std::wstring& pathW){
  // Windows device interface paths are case-insensitive. Normalize to lowercase.
  return to_lower(wstr_to_utf8(pathW));
}

static void dump_caps(const HIDP_CAPS& c){
  dbg_printf("[WinHID] CAPS: UsagePage=%u Usage=%u InLen=%u OutLen=%u FeatLen=%u",
             c.UsagePage, c.Usage, c.InputReportByteLength, c.OutputReportByteLength, c.FeatureReportByteLength);
}

static std::string guid_to_str(const GUID& g){
  char b[64];
  _snprintf_s(b, sizeof(b), _TRUNCATE,
    "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
    g.Data1, g.Data2, g.Data3,
    g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
  return b;
}

static bool get_container_id(HDEVINFO di, const SP_DEVINFO_DATA& dd, std::string& out){
  DEVPROPTYPE type = 0;
  GUID gid{};
  DWORD sz = 0;
  if (!SetupDiGetDevicePropertyW(di, const_cast<SP_DEVINFO_DATA*>(&dd),
        &DEVPKEY_Device_ContainerId, &type, (PBYTE)&gid, sizeof(gid), &sz, 0))
    return false;
  if (type != DEVPROP_TYPE_GUID) return false;
  out = guid_to_str(gid);
  return true;
}

static std::string get_devinst_fallback(const SP_DEVINFO_DATA& dd){
  wchar_t id[512];
  if (CM_Get_Device_IDW(dd.DevInst, id, 512, 0) == CR_SUCCESS) return wstr_to_utf8(id);
  return {};
}

static std::string last_error_str(DWORD err = GetLastError()) {
  LPSTR msg = nullptr;
  DWORD len = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, nullptr);
  std::string s = len ? std::string(msg, len) : std::string("Unknown error");
  if (msg) LocalFree(msg);
  return s;
}

std::string WinHID::WToU8(const wchar_t* w){ return wstr_to_utf8(w); }
std::string WinHID::WToU8(const std::wstring& w){ return wstr_to_utf8(w); }

// Resolve containerId for a given interface path.
static bool resolve_container_from_interface_path(const std::wstring& pathW, std::string& containerOut){
  GUID hidGuid; HidD_GetHidGuid(&hidGuid);
  HDEVINFO di = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (di == INVALID_HANDLE_VALUE) return false;

  SP_DEVICE_INTERFACE_DATA ifData{}; ifData.cbSize = sizeof(ifData);
  if (!SetupDiOpenDeviceInterfaceW(di, pathW.c_str(), 0, &ifData)) {
    SetupDiDestroyDeviceInfoList(di);
    return false;
  }

  DWORD req = 0;
  SetupDiGetDeviceInterfaceDetailW(di, &ifData, nullptr, 0, &req, nullptr);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || req == 0) {
    SetupDiDestroyDeviceInfoList(di);
    return false;
  }

  std::vector<BYTE> buf(req);
  auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buf.data());
  detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
  SP_DEVINFO_DATA devData{}; devData.cbSize = sizeof(devData);
  if (!SetupDiGetDeviceInterfaceDetailW(di, &ifData, detail, req, nullptr, &devData)) {
    SetupDiDestroyDeviceInfoList(di);
    return false;
  }

  bool ok = get_container_id(di, devData, containerOut);
  if (!ok) containerOut = get_devinst_fallback(devData);

  SetupDiDestroyDeviceInfoList(di);
  return !containerOut.empty();
}

// ---------- OpenHid/GetCaps ----------
bool WinHID::OpenHid(const std::wstring& path, HANDLE& out) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, 0, nullptr);
  }
  if (h == INVALID_HANDLE_VALUE) {
    h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  }
  if (h == INVALID_HANDLE_VALUE) {
    h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, 0, nullptr);
  }
  if (h == INVALID_HANDLE_VALUE) return false;
  out = h;
  return true;
}

bool WinHID::GetCaps(HANDLE h, USHORT& usagePage, USHORT& usage, USHORT& inLen) {
  PHIDP_PREPARSED_DATA prep = nullptr;
  HIDP_CAPS caps{};
  if (!HidD_GetPreparsedData(h, &prep)) return false;
  NTSTATUS st = HidP_GetCaps(prep, &caps);
  if (st != HIDP_STATUS_SUCCESS) { HidD_FreePreparsedData(prep); return false; }
  usagePage = caps.UsagePage;
  usage     = caps.Usage;
  inLen     = caps.InputReportByteLength;
  dump_caps(caps);
  HidD_FreePreparsedData(prep);
  return inLen > 0;
}

// ---------- ctor/dtor and class ----------
WinHID::WinHID(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<WinHID>(info) { dbg_init(); }

WinHID::~WinHID() { stopAll(); }

Napi::Function WinHID::GetClass(Napi::Env env) {
  return DefineClass(env, "WinHID", {
    InstanceMethod("getDevices", &WinHID::GetDevices),
    InstanceMethod("startListening", &WinHID::StartListening),
    InstanceMethod("stopListening", &WinHID::StopListening),
  });
}

// ---------- device enumeration API ----------
Napi::Value WinHID::GetDevices(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  GUID hidGuid; HidD_GetHidGuid(&hidGuid);
  HDEVINFO devInfo = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (devInfo == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "SetupDiGetClassDevs failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Array result = Napi::Array::New(env);
  DWORD index = 0;
  SP_DEVICE_INTERFACE_DATA ifData; ifData.cbSize = sizeof(ifData);

  while (SetupDiEnumDeviceInterfaces(devInfo, nullptr, &hidGuid, index, &ifData)) {
    ++index;

    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, nullptr, 0, &requiredSize, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0) continue;

    std::vector<BYTE> buffer(requiredSize);
    auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    SP_DEVINFO_DATA devData; devData.cbSize = sizeof(devData);
    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, requiredSize, nullptr, &devData)) continue;

    std::wstring devicePathW(detail->DevicePath);
    std::string devicePathNorm = normalize_path_u8(devicePathW);

    HANDLE h = CreateFileW(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      h = CreateFileW(detail->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                      OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    }

    USHORT vid = 0, pid = 0, usagePage = 0, usage = 0;
    std::string manufacturer, product, serial;

    std::string containerId;
    if (!get_container_id(devInfo, devData, containerId)) {
      containerId = get_devinst_fallback(devData);
    }

    if (h != INVALID_HANDLE_VALUE) {
      HIDD_ATTRIBUTES attrs{}; attrs.Size = sizeof(attrs);
      if (HidD_GetAttributes(h, &attrs)) { vid = attrs.VendorID; pid = attrs.ProductID; }

      USHORT inLen=0; GetCaps(h, usagePage, usage, inLen);

      wchar_t wbuf[256];
      if (HidD_GetManufacturerString(h, wbuf, sizeof(wbuf))) manufacturer = wstr_to_utf8(wbuf);
      if (HidD_GetProductString(h, wbuf, sizeof(wbuf)))      product      = wstr_to_utf8(wbuf);
      if (HidD_GetSerialNumberString(h, wbuf, sizeof(wbuf))) serial       = wstr_to_utf8(wbuf);
      CloseHandle(h);
    }

    Napi::Object dev = Napi::Object::New(env);
    dev.Set("path", devicePathNorm); // normalized
    dev.Set("vendorId", Napi::Number::New(env, vid));
    dev.Set("productId", Napi::Number::New(env, pid));
    dev.Set("usagePage", Napi::Number::New(env, usagePage));
    dev.Set("usage", Napi::Number::New(env, usage));
    dev.Set("containerId", Napi::String::New(env, containerId));
    if (!manufacturer.empty()) dev.Set("manufacturer", Napi::String::New(env, manufacturer));
    if (!product.empty())      dev.Set("product",      Napi::String::New(env, product));
    if (!serial.empty())       dev.Set("serialNumber", Napi::String::New(env, serial));

    result.Set(result.Length(), dev);
  }

  SetupDiDestroyDeviceInfoList(devInfo);
  return result;
}

// ---------- reader thread ----------
void WinHID::RunReader(std::shared_ptr<Listener> L) {
  PHIDP_PREPARSED_DATA prep = nullptr;
  if (!HidD_GetPreparsedData(L->handle, &prep)) return;

  HIDP_CAPS caps{};
  if (HidP_GetCaps(prep, &caps) != HIDP_STATUS_SUCCESS) { HidD_FreePreparsedData(prep); return; }

  USHORT numBtnCaps = caps.NumberInputButtonCaps;
  std::vector<HIDP_BUTTON_CAPS> btnCaps(numBtnCaps ? numBtnCaps : 1);
  if (numBtnCaps) {
    NTSTATUS st = HidP_GetButtonCaps(HidP_Input, btnCaps.data(), &numBtnCaps, prep);
    if (st != HIDP_STATUS_SUCCESS) numBtnCaps = 0;
  }

  std::vector<BYTE> report(caps.InputReportByteLength);
  std::unordered_map<UCHAR, std::vector<BYTE>> lastById;

  OVERLAPPED ov{}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!ov.hEvent) { HidD_FreePreparsedData(prep); return; }

  bool hasReportIDs = false;
  std::unordered_set<UCHAR> validReportIDs;
  for (USHORT i = 0; i < numBtnCaps; ++i) {
    const auto& bc = btnCaps[i];
    if (bc.ReportID != 0) hasReportIDs = true;
    validReportIDs.insert((UCHAR)bc.ReportID);
  }

  auto getRid = [&](const std::vector<BYTE>& src)->UCHAR {
    if (!hasReportIDs || src.empty()) return 0; return src[0];
  };

  auto collectUsages = [&](const std::vector<BYTE>& src, std::unordered_set<USHORT>& out){
    if (src.empty()) return;
    UCHAR rid = getRid(src);
    if (hasReportIDs && !validReportIDs.empty() && !validReportIDs.count(rid)) return;
    for (USHORT i = 0; i < numBtnCaps; ++i) {
      const auto& bc = btnCaps[i];
      if (bc.UsagePage != HID_USAGE_PAGE_BUTTON) continue;
      if (bc.ReportID != rid) continue;
      ULONG cnt = HidP_MaxUsageListLength(HidP_Input, bc.UsagePage, prep);
      if (!cnt) continue;
      std::vector<USAGE> usages(cnt);
      NTSTATUS s = HidP_GetUsages(HidP_Input, bc.UsagePage, bc.LinkCollection,
                                  usages.data(), &cnt, prep, (PCHAR)src.data(), (ULONG)src.size());
      if (s == HIDP_STATUS_SUCCESS && cnt) for (ULONG k=0;k<cnt;++k) out.insert((USHORT)usages[k]);
    }
  };

  while (!L->stop.load()) {
    DWORD bytesRead = 0;
    ResetEvent(ov.hEvent);
    BOOL ok = ReadFile(L->handle, report.data(), (DWORD)report.size(), nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(ov.hEvent, 20);
        if (wait == WAIT_OBJECT_0) GetOverlappedResult(L->handle, &ov, &bytesRead, FALSE);
        else if (wait == WAIT_TIMEOUT) continue;
        else break;
      } else break;
    } else {
      GetOverlappedResult(L->handle, &ov, &bytesRead, TRUE);
    }
    if (!bytesRead) continue;

    UCHAR rid = getRid(report);
    std::unordered_set<USHORT> pressed, prevPressed;
    collectUsages(report, pressed);
    auto itPrev = lastById.find(rid);
    if (itPrev != lastById.end()) collectUsages(itPrev->second, prevPressed);

    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();

    for (auto u : pressed) if (!prevPressed.count(u)) {
      L->tsfn.BlockingCall([L, u, now](Napi::Env env, Napi::Function cb){
        Napi::Object evt = Napi::Object::New(env);
        evt.Set("path", Napi::String::New(env, L->pathNormU8));         // normalized
        evt.Set("usagePage", Napi::Number::New(env, L->usagePage));
        evt.Set("usage", Napi::Number::New(env, L->usage));
        evt.Set("button", Napi::Number::New(env, u));
        evt.Set("pressed", Napi::Boolean::New(env, true));
        evt.Set("timestamp", Napi::Number::New(env, (double)now));
        // identity extras to avoid mislabel
        if (L->vid) evt.Set("vendorId", Napi::Number::New(env, L->vid));
        if (L->pid) evt.Set("productId", Napi::Number::New(env, L->pid));
        if (!L->containerId.empty()) evt.Set("containerId", Napi::String::New(env, L->containerId));
        if (!L->product.empty())     evt.Set("product",     Napi::String::New(env, L->product));
        if (!L->manufacturer.empty())evt.Set("manufacturer",Napi::String::New(env, L->manufacturer));
        cb.Call({ evt });
      });
    }
    for (auto u : prevPressed) if (!pressed.count(u)) {
      L->tsfn.BlockingCall([L, u, now](Napi::Env env, Napi::Function cb){
        Napi::Object evt = Napi::Object::New(env);
        evt.Set("path", Napi::String::New(env, L->pathNormU8));
        evt.Set("usagePage", Napi::Number::New(env, L->usagePage));
        evt.Set("usage", Napi::Number::New(env, L->usage));
        evt.Set("button", Napi::Number::New(env, u));
        evt.Set("pressed", Napi::Boolean::New(env, false));
        evt.Set("timestamp", Napi::Number::New(env, (double)now));
        if (L->vid) evt.Set("vendorId", Napi::Number::New(env, L->vid));
        if (L->pid) evt.Set("productId", Napi::Number::New(env, L->pid));
        if (!L->containerId.empty()) evt.Set("containerId", Napi::String::New(env, L->containerId));
        if (!L->product.empty())     evt.Set("product",     Napi::String::New(env, L->product));
        if (!L->manufacturer.empty())evt.Set("manufacturer",Napi::String::New(env, L->manufacturer));
        cb.Call({ evt });
      });
    }

    lastById[rid] = report;
  }

  if (ov.hEvent) CloseHandle(ov.hEvent);
  HidD_FreePreparsedData(prep);
}

// ---------- hot-plug helpers ----------
void WinHID::startReaderForPath(const std::wstring& pathW) {
  const std::string pathNorm = normalize_path_u8(pathW);

  {
    std::lock_guard<std::mutex> lock(listeners_mtx_);
    if (listeners_.count(pathNorm)) return;
  }

  HANDLE h = INVALID_HANDLE_VALUE;
  if (!OpenHid(pathW, h)) return;

  HidD_SetNumInputBuffers(h, 64);

  auto L = std::make_shared<Listener>();
  L->pathW = pathW;
  L->pathNormU8 = pathNorm;
  L->handle = h;

  // identity
  HIDD_ATTRIBUTES a{}; a.Size = sizeof(a);
  if (HidD_GetAttributes(h, &a)) { L->vid = a.VendorID; L->pid = a.ProductID; }
  resolve_container_from_interface_path(pathW, L->containerId);

  wchar_t wbuf[256];
  if (HidD_GetManufacturerString(h, wbuf, sizeof(wbuf))) L->manufacturer = wstr_to_utf8(wbuf);
  if (HidD_GetProductString(h, wbuf, sizeof(wbuf)))      L->product      = wstr_to_utf8(wbuf);
  if (HidD_GetSerialNumberString(h, wbuf, sizeof(wbuf))) L->serial       = wstr_to_utf8(wbuf);

  // caps
  if (!GetCaps(h, L->usagePage, L->usage, L->inputReportLen)) { CloseHandle(h); return; }

  // filter
  if ((wantVid_ && L->vid != wantVid_) ||
      (wantPid_ && L->pid != wantPid_) ||
      (wantUsagePage_ && L->usagePage != wantUsagePage_) ||
      (wantUsage_ && L->usage != wantUsage_)) {
    CloseHandle(h);
    return;
  }

  if (!tsfn_ready_) { CloseHandle(h); return; }

  tsfn_.Acquire();
  L->tsfn = tsfn_;
  L->prevReport.assign(L->inputReportLen, 0);

  L->th = std::thread([L]{ RunReader(L); });

  std::lock_guard<std::mutex> lock(listeners_mtx_);
  listeners_[pathNorm] = std::move(L);
}

void WinHID::stopReaderForPath(const std::wstring& pathW) {
  const std::string key = normalize_path_u8(pathW);
  std::shared_ptr<Listener> L;
  {
    std::lock_guard<std::mutex> lock(listeners_mtx_);
    auto it = listeners_.find(key);
    if (it == listeners_.end()) return;
    L = it->second;
    listeners_.erase(it);
  }
  if (!L) return;
  L->stop.store(true);
  if (L->handle != INVALID_HANDLE_VALUE) CancelIoEx(L->handle, nullptr);
  if (L->th.joinable()) L->th.join();
  if (L->tsfn) L->tsfn.Release();
  if (L->handle != INVALID_HANDLE_VALUE) CloseHandle(L->handle);
}

// ---------- PnP callback ----------
DWORD CALLBACK WinHID::OnPnpEvent(HCMNOTIFICATION, PVOID ctx,
                                  CM_NOTIFY_ACTION action,
                                  PCM_NOTIFY_EVENT_DATA data, DWORD) {
  auto* self = static_cast<WinHID*>(ctx);
  if (!self || !data || data->FilterType != CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE) return ERROR_SUCCESS;
  if (!data->u.DeviceInterface.SymbolicLink[0]) return ERROR_SUCCESS;

  std::wstring pathW = data->u.DeviceInterface.SymbolicLink;

  if (action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL) {
    self->startReaderForPath(pathW);
  } else if (action == CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL) {
    self->stopReaderForPath(pathW);
  }
  return ERROR_SUCCESS;
}

// ---------- API: start/stop ----------
Napi::Value WinHID::StartListening(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (tsfn_ready_) stopAll();

  int cbIndex = (info.Length() >= 1 && info[0].IsFunction()) ? 0 : 1;
  if (info.Length() <= cbIndex || !info[cbIndex].IsFunction()) {
    Napi::TypeError::New(env, "callback function is required").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  Napi::Function cb = info[cbIndex].As<Napi::Function>();

  wantVid_ = wantPid_ = wantUsagePage_ = wantUsage_ = 0;
  if (cbIndex == 1 && info[0].IsObject()) {
    Napi::Object f = info[0].As<Napi::Object>();
    if (f.Has("vendorId"))   wantVid_       = (USHORT)f.Get("vendorId").ToNumber().Uint32Value();
    if (f.Has("productId"))  wantPid_       = (USHORT)f.Get("productId").ToNumber().Uint32Value();
    if (f.Has("usagePage"))  wantUsagePage_ = (USHORT)f.Get("usagePage").ToNumber().Uint32Value();
    if (f.Has("usage"))      wantUsage_     = (USHORT)f.Get("usage").ToNumber().Uint32Value();
  }

  tsfn_ = Napi::ThreadSafeFunction::New(env, cb, "hid-button-listener", 0, 1);
  tsfn_ready_ = true;

  // initial enumeration
  GUID hidGuid; HidD_GetHidGuid(&hidGuid);
  HDEVINFO devInfo = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (devInfo == INVALID_HANDLE_VALUE) {
    if (tsfn_ready_) { tsfn_.Release(); tsfn_ = Napi::ThreadSafeFunction(); tsfn_ready_ = false; }
    Napi::Error::New(env, "SetupDiGetClassDevs failed").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  DWORD index = 0;
  SP_DEVICE_INTERFACE_DATA ifData; ifData.cbSize = sizeof(ifData);

  while (SetupDiEnumDeviceInterfaces(devInfo, nullptr, &hidGuid, index, &ifData)) {
    ++index;
    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, nullptr, 0, &requiredSize, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0) continue;
    std::vector<BYTE> buffer(requiredSize);
    auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    SP_DEVINFO_DATA devData; devData.cbSize = sizeof(devData);
    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, requiredSize, nullptr, &devData)) continue;
    startReaderForPath(detail->DevicePath);
  }
  SetupDiDestroyDeviceInfoList(devInfo);

  // register PnP notifications
  if (!pnpNotify_) {
    CM_NOTIFY_FILTER filter{}; filter.cbSize = sizeof(filter);
    filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
    filter.u.DeviceInterface.ClassGuid = hidGuid;
    CONFIGRET cr = CM_Register_Notification(&filter, this, &WinHID::OnPnpEvent, &pnpNotify_);
    if (cr != CR_SUCCESS) dbg_printf("[WinHID] CM_Register_Notification failed: 0x%X", (unsigned)cr);
  }

  return env.Undefined();
}

void WinHID::stopAll() {
  if (pnpNotify_) { CM_Unregister_Notification(pnpNotify_); pnpNotify_ = nullptr; }

  std::unordered_map<std::string, std::shared_ptr<Listener>> toStop;
  {
    std::lock_guard<std::mutex> lock(listeners_mtx_);
    toStop.swap(listeners_);
  }

  for (auto& kv : toStop) {
    auto& L = kv.second;
    if (!L) continue;
    L->stop.store(true);
    if (L->handle != INVALID_HANDLE_VALUE) CancelIoEx(L->handle, nullptr);
  }
  for (auto& kv : toStop) {
    auto& L = kv.second;
    if (!L) continue;
    if (L->th.joinable()) L->th.join();
    if (L->tsfn) L->tsfn.Release();
    if (L->handle != INVALID_HANDLE_VALUE) { CloseHandle(L->handle); L->handle = INVALID_HANDLE_VALUE; }
  }

  if (tsfn_ready_) { tsfn_.Release(); tsfn_ = Napi::ThreadSafeFunction(); tsfn_ready_ = false; }
}

Napi::Value WinHID::StopListening(const Napi::CallbackInfo& info) {
  stopAll();
  return info.Env().Undefined();
}

// ---------- addon init ----------
Napi::Object Init(Napi::Env env, Napi::Object exports)
{
  exports.Set(Napi::String::New(env, "WinHID"), WinHID::GetClass(env));
  return exports;
}
NODE_API_MODULE(addon, Init)

#endif
