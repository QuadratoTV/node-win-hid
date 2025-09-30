#ifdef _WIN32
#define NOMINMAX
#include "WinHID.h"
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidusage.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <cstdarg>
#include <cstdio>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "cfgmgr32.lib")

// ---------- debug helpers ----------
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
  // stderr
  fputs(buf, stderr);
  fputc('\n', stderr);
  // debugger
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

static const char* tf(BOOLEAN b){ return b ? "1" : "0"; }

static void dump_caps(const HIDP_CAPS& c){
  dbg_printf("[WinHID] CAPS:"
             " UsagePage=%u Usage=%u"
             " InputReportByteLength=%u OutputReportByteLength=%u FeatureReportByteLength=%u"
             " NumberLinkCollectionNodes=%u"
             " NumberInputButtonCaps=%u NumberInputValueCaps=%u NumberInputDataIndices=%u"
             " NumberOutputButtonCaps=%u NumberOutputValueCaps=%u NumberOutputDataIndices=%u"
             " NumberFeatureButtonCaps=%u NumberFeatureValueCaps=%u NumberFeatureDataIndices=%u",
             c.UsagePage, c.Usage,
             c.InputReportByteLength, c.OutputReportByteLength, c.FeatureReportByteLength,
             c.NumberLinkCollectionNodes,
             c.NumberInputButtonCaps, c.NumberInputValueCaps, c.NumberInputDataIndices,
             c.NumberOutputButtonCaps, c.NumberOutputValueCaps, c.NumberOutputDataIndices,
             c.NumberFeatureButtonCaps, c.NumberFeatureValueCaps, c.NumberFeatureDataIndices);
}

static void dump_button_cap(const HIDP_BUTTON_CAPS& bc, const char* kind){
  if (bc.IsRange) {
    dbg_printf("[WinHID] %s BUTTON_CAP: ReportID=%u UsagePage=%u LinkCollection=%u IsAlias=%s IsRange=1 "
               "UsageMin=%u UsageMax=%u StringMin=%u StringMax=%u DesignatorMin=%u DesignatorMax=%u "
               "DataIndexMin=%u DataIndexMax=%u IsAbsolute=%s",
               kind, bc.ReportID, bc.UsagePage, bc.LinkCollection, tf(bc.IsAlias),
               bc.Range.UsageMin, bc.Range.UsageMax, bc.Range.StringMin, bc.Range.StringMax,
               bc.Range.DesignatorMin, bc.Range.DesignatorMax,
               bc.Range.DataIndexMin, bc.Range.DataIndexMax, tf(bc.IsAbsolute));
  } else {
    dbg_printf("[WinHID] %s BUTTON_CAP: ReportID=%u UsagePage=%u LinkCollection=%u IsAlias=%s IsRange=0 "
               "Usage=%u StringIndex=%u DesignatorIndex=%u DataIndex=%u IsAbsolute=%s",
               kind, bc.ReportID, bc.UsagePage, bc.LinkCollection, tf(bc.IsAlias),
               bc.NotRange.Usage, bc.NotRange.StringIndex, bc.NotRange.DesignatorIndex,
               bc.NotRange.DataIndex, tf(bc.IsAbsolute));
  }
}

static void dump_all_button_caps(PHIDP_PREPARSED_DATA prep){
  // Input
  USHORT n = 0;
  HidP_GetButtonCaps(HidP_Input, nullptr, &n, prep);
  if (n) {
    std::vector<HIDP_BUTTON_CAPS> v(n);
    if (HidP_GetButtonCaps(HidP_Input, v.data(), &n, prep) == HIDP_STATUS_SUCCESS) {
      for (USHORT i = 0; i < n; ++i) dump_button_cap(v[i], "INPUT");
    }
  }
  // Output
  n = 0; HidP_GetButtonCaps(HidP_Output, nullptr, &n, prep);
  if (n) {
    std::vector<HIDP_BUTTON_CAPS> v(n);
    if (HidP_GetButtonCaps(HidP_Output, v.data(), &n, prep) == HIDP_STATUS_SUCCESS) {
      for (USHORT i = 0; i < n; ++i) dump_button_cap(v[i], "OUTPUT");
    }
  }
  // Feature
  n = 0; HidP_GetButtonCaps(HidP_Feature, nullptr, &n, prep);
  if (n) {
    std::vector<HIDP_BUTTON_CAPS> v(n);
    if (HidP_GetButtonCaps(HidP_Feature, v.data(), &n, prep) == HIDP_STATUS_SUCCESS) {
      for (USHORT i = 0; i < n; ++i) dump_button_cap(v[i], "FEATURE");
    }
  }
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

static std::string get_devinst_id(const SP_DEVINFO_DATA& dd){
  wchar_t id[512]; ULONG len = 0;
  if (CM_Get_Device_IDW(dd.DevInst, id, 512, 0) == CR_SUCCESS) return wstr_to_utf8(id);
  return {};
}

static std::string make_device_key(const std::string& containerId,
                                   USHORT vid, USHORT pid,
                                   const std::string& serial){
  char b[256];
  _snprintf_s(b, sizeof(b), _TRUNCATE, "CID=%s VID=0x%04X PID=0x%04X SN=%s",
              containerId.empty() ? "-" : containerId.c_str(),
              vid, pid,
              serial.empty() ? "-" : serial.c_str());
  return b;
}

// keyed dumps
static void dump_caps_k(const std::string& key, const HIDP_CAPS& c){
  dbg_printf("[HID %s] CAPS: UsagePage=%u Usage=%u InputReportByteLength=%u OutputReportByteLength=%u FeatureReportByteLength=%u NumberLinkCollectionNodes=%u NumberInputButtonCaps=%u NumberInputValueCaps=%u NumberInputDataIndices=%u NumberOutputButtonCaps=%u NumberOutputValueCaps=%u NumberOutputDataIndices=%u NumberFeatureButtonCaps=%u NumberFeatureValueCaps=%u NumberFeatureDataIndices=%u",
             key.c_str(), c.UsagePage, c.Usage,
             c.InputReportByteLength, c.OutputReportByteLength, c.FeatureReportByteLength,
             c.NumberLinkCollectionNodes,
             c.NumberInputButtonCaps, c.NumberInputValueCaps, c.NumberInputDataIndices,
             c.NumberOutputButtonCaps, c.NumberOutputValueCaps, c.NumberOutputDataIndices,
             c.NumberFeatureButtonCaps, c.NumberFeatureValueCaps, c.NumberFeatureDataIndices);
}

static void dump_button_cap_k(const std::string& key, const char* kind, const HIDP_BUTTON_CAPS& bc){
  if (bc.IsRange) {
    dbg_printf("[HID %s] %s BUTTON_CAP: ReportID=%u UsagePage=%u LinkCollection=%u IsAlias=%u IsRange=1 UsageMin=%u UsageMax=%u StringMin=%u StringMax=%u DesignatorMin=%u DesignatorMax=%u DataIndexMin=%u DataIndexMax=%u IsAbsolute=%u",
               key.c_str(), kind, bc.ReportID, bc.UsagePage, bc.LinkCollection, (unsigned)bc.IsAlias,
               bc.Range.UsageMin, bc.Range.UsageMax, bc.Range.StringMin, bc.Range.StringMax,
               bc.Range.DesignatorMin, bc.Range.DesignatorMax,
               bc.Range.DataIndexMin, bc.Range.DataIndexMax, (unsigned)bc.IsAbsolute);
  } else {
    dbg_printf("[HID %s] %s BUTTON_CAP: ReportID=%u UsagePage=%u LinkCollection=%u IsAlias=%u IsRange=0 Usage=%u StringIndex=%u DesignatorIndex=%u DataIndex=%u IsAbsolute=%u",
               key.c_str(), kind, bc.ReportID, bc.UsagePage, bc.LinkCollection, (unsigned)bc.IsAlias,
               bc.NotRange.Usage, bc.NotRange.StringIndex, bc.NotRange.DesignatorIndex,
               bc.NotRange.DataIndex, (unsigned)bc.IsAbsolute);
  }
}

static void dump_all_button_caps_k(const std::string& key, PHIDP_PREPARSED_DATA prep){
  USHORT n = 0;

  n = 0; HidP_GetButtonCaps(HidP_Input, nullptr, &n, prep);
  if (n){ std::vector<HIDP_BUTTON_CAPS> v(n);
    if (HidP_GetButtonCaps(HidP_Input, v.data(), &n, prep) == HIDP_STATUS_SUCCESS)
      for (USHORT i=0;i<n;++i) dump_button_cap_k(key, "INPUT", v[i]);
  }
  n = 0; HidP_GetButtonCaps(HidP_Output, nullptr, &n, prep);
  if (n){ std::vector<HIDP_BUTTON_CAPS> v(n);
    if (HidP_GetButtonCaps(HidP_Output, v.data(), &n, prep) == HIDP_STATUS_SUCCESS)
      for (USHORT i=0;i<n;++i) dump_button_cap_k(key, "OUTPUT", v[i]);
  }
  n = 0; HidP_GetButtonCaps(HidP_Feature, nullptr, &n, prep);
  if (n){ std::vector<HIDP_BUTTON_CAPS> v(n);
    if (HidP_GetButtonCaps(HidP_Feature, v.data(), &n, prep) == HIDP_STATUS_SUCCESS)
      for (USHORT i=0;i<n;++i) dump_button_cap_k(key, "FEATURE", v[i]);
  }
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

bool WinHID::OpenHid(const std::wstring& path, HANDLE& out) {
  dbg_printf("[WinHID] OpenHid: trying RW overlapped: %s", wstr_to_utf8(path).c_str());
  HANDLE h = CreateFileW(path.c_str(),
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING,
                         FILE_FLAG_OVERLAPPED, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    dbg_printf("[WinHID] OpenHid: RW overlapped failed: %s", last_error_str().c_str());
    dbg_printf("[WinHID] OpenHid: trying RW non-overlapped");
    h = CreateFileW(path.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING,
                    0, nullptr);
  }
  if (h == INVALID_HANDLE_VALUE) {
    dbg_printf("[WinHID] OpenHid: RW non-overlapped failed: %s", last_error_str().c_str());
    dbg_printf("[WinHID] OpenHid: trying RO overlapped");
    h = CreateFileW(path.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED, nullptr);
  }
  if (h == INVALID_HANDLE_VALUE) {
    dbg_printf("[WinHID] OpenHid: RO overlapped failed: %s", last_error_str().c_str());
    dbg_printf("[WinHID] OpenHid: trying RO non-overlapped");
    h = CreateFileW(path.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING,
                    0, nullptr);
  }
  if (h == INVALID_HANDLE_VALUE) {
    dbg_printf("[WinHID] OpenHid: all attempts failed");
    return false;
  }
  dbg_printf("[WinHID] OpenHid: success");
  out = h;
  return true;
}

bool WinHID::GetCaps(HANDLE h, USHORT& usagePage, USHORT& usage, USHORT& inLen) {
  PHIDP_PREPARSED_DATA prep = nullptr;
  HIDP_CAPS caps{};
  if (!HidD_GetPreparsedData(h, &prep)) {
    dbg_printf("[WinHID] GetCaps: HidD_GetPreparsedData failed: %s", last_error_str().c_str());
    return false;
  }
  NTSTATUS st = HidP_GetCaps(prep, &caps);
  if (st != HIDP_STATUS_SUCCESS) {
    dbg_printf("[WinHID] GetCaps: HidP_GetCaps failed: 0x%08X", (unsigned)st);
    HidD_FreePreparsedData(prep);
    return false;
  }

  usagePage = caps.UsagePage;
  usage = caps.Usage;
  inLen = caps.InputReportByteLength;

  dump_caps(caps);
  dump_all_button_caps(prep);

  HidD_FreePreparsedData(prep);
  return inLen > 0;
}

// ---------- ctor and class ----------
WinHID::WinHID(const Napi::CallbackInfo& info)
  : Napi::ObjectWrap<WinHID>(info) { dbg_init(); }

Napi::Function WinHID::GetClass(Napi::Env env) {
  return DefineClass(env, "WinHID", {
    InstanceMethod("getDevices", &WinHID::GetDevices),
    InstanceMethod("startListening", &WinHID::StartListening),
    InstanceMethod("stopListening", &WinHID::StopListening),
  });
}

Napi::Value WinHID::GetDevices(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  GUID hidGuid;
  HidD_GetHidGuid(&hidGuid);

  HDEVINFO devInfo = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (devInfo == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "SetupDiGetClassDevs failed").ThrowAsJavaScriptException();
    return env.Null();
  }

  Napi::Array result = Napi::Array::New(env);
  DWORD index = 0;
  SP_DEVICE_INTERFACE_DATA ifData;
  ifData.cbSize = sizeof(ifData);

  while (SetupDiEnumDeviceInterfaces(devInfo, nullptr, &hidGuid, index, &ifData)) {
    ++index;

    // First call to get required size
    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, nullptr, 0, &requiredSize, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0) {
      dbg_printf("[WinHID] GetDevices: detail size query failed at idx=%lu: %s", index-1, last_error_str().c_str());
      continue;
    }

    std::vector<BYTE> buffer(requiredSize);
    auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    SP_DEVINFO_DATA devData;
    devData.cbSize = sizeof(devData);

    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, requiredSize, nullptr, &devData)) {
      dbg_printf("[WinHID] GetDevices: SetupDiGetDeviceInterfaceDetailW failed at idx=%lu: %s", index-1, last_error_str().c_str());
      continue;
    }

    std::wstring devicePathW(detail->DevicePath);
    std::string devicePath = wstr_to_utf8(devicePathW);

    // Open device to query attributes and strings
    HANDLE h = CreateFileW(detail->DevicePath,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
      // Try read-only
      h = CreateFileW(detail->DevicePath,
                      0,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      nullptr,
                      OPEN_EXISTING,
                      FILE_FLAG_OVERLAPPED,
                      nullptr);
    }

    USHORT vid = 0, pid = 0;
    USHORT usagePage = 0, usage = 0;
    std::string manufacturer, product, serial;

    std::string containerId;
    if (!get_container_id(devInfo, devData, containerId)) {
      // fallback to DevInst ID
      containerId = get_devinst_id(devData);
    }

    // compute key once per interface node
    const std::string deviceKey = make_device_key(containerId, vid, pid, serial);

    if (h != INVALID_HANDLE_VALUE) {
      HIDD_ATTRIBUTES attrs;
      attrs.Size = sizeof(attrs);
      if (HidD_GetAttributes(h, &attrs)) {
        vid = attrs.VendorID;
        pid = attrs.ProductID;
      } else {
        dbg_printf("[WinHID] GetDevices: HidD_GetAttributes failed for %s", devicePath.c_str());
      }

      PHIDP_PREPARSED_DATA prep = nullptr;
      HIDP_CAPS caps;
      if (HidD_GetPreparsedData(h, &prep)) {
        if (HidP_GetCaps(prep, &caps) == HIDP_STATUS_SUCCESS) {
          usagePage = caps.UsagePage;
          usage = caps.Usage;

          dump_caps_k(deviceKey, caps);
          dump_all_button_caps_k(deviceKey, prep);
        } else {
          dbg_printf("[WinHID] GetDevices: HidP_GetCaps failed for %s", devicePath.c_str());
        }
        HidD_FreePreparsedData(prep);
      } else {
        dbg_printf("[WinHID] GetDevices: HidD_GetPreparsedData failed for %s", devicePath.c_str());
      }

      wchar_t wbuf[256];
      if (HidD_GetManufacturerString(h, wbuf, sizeof(wbuf))) {
        manufacturer = wstr_to_utf8(wbuf);
      }
      if (HidD_GetProductString(h, wbuf, sizeof(wbuf))) {
        product = wstr_to_utf8(wbuf);
      }
      if (HidD_GetSerialNumberString(h, wbuf, sizeof(wbuf))) {
        serial = wstr_to_utf8(wbuf);
      }

      CloseHandle(h);
    } else {
      dbg_printf("[WinHID] GetDevices: CreateFileW failed for %s: %s", devicePath.c_str(), last_error_str().c_str());
    }

    Napi::Object dev = Napi::Object::New(env);
    dev.Set("path", devicePath);
    dev.Set("vendorId", Napi::Number::New(env, vid));
    dev.Set("productId", Napi::Number::New(env, pid));
    dev.Set("usagePage", Napi::Number::New(env, usagePage));
    dev.Set("usage", Napi::Number::New(env, usage));
    dev.Set("deviceKey", Napi::String::New(env, deviceKey));
    dev.Set("containerId", Napi::String::New(env, containerId)); // optional but useful
    if (!manufacturer.empty()) dev.Set("manufacturer", Napi::String::New(env, manufacturer));
    if (!product.empty())      dev.Set("product", Napi::String::New(env, product));
    if (!serial.empty())       dev.Set("serialNumber", Napi::String::New(env, serial));

    result.Set(result.Length(), dev);
  }

  SetupDiDestroyDeviceInfoList(devInfo);
  return result;
}

// ---------- reader thread ----------
void WinHID::RunReader(std::shared_ptr<Listener> L) {
  dbg_printf("[WinHID] RunReader: starting for %s", wstr_to_utf8(L->pathW).c_str());

  PHIDP_PREPARSED_DATA prep = nullptr;
  if (!HidD_GetPreparsedData(L->handle, &prep)) {
    dbg_printf("[WinHID] RunReader: HidD_GetPreparsedData failed at start: %s", last_error_str().c_str());
    return;
  }

  HIDP_CAPS caps{};
  if (HidP_GetCaps(prep, &caps) != HIDP_STATUS_SUCCESS) {
    dbg_printf("[WinHID] RunReader: HidP_GetCaps failed");
    HidD_FreePreparsedData(prep);
    return;
  }

  USHORT numBtnCaps = caps.NumberInputButtonCaps;
  std::vector<HIDP_BUTTON_CAPS> btnCaps(numBtnCaps ? numBtnCaps : 1);
  if (numBtnCaps) {
    NTSTATUS st = HidP_GetButtonCaps(HidP_Input, btnCaps.data(), &numBtnCaps, prep);
    if (st != HIDP_STATUS_SUCCESS) {
      dbg_printf("[WinHID] RunReader: HidP_GetButtonCaps failed: 0x%08X", (unsigned)st);
      numBtnCaps = 0;
    }
  }
  dbg_printf("[WinHID] RunReader: InLen=%u ButtonCaps=%u", caps.InputReportByteLength, numBtnCaps);

  // Determine whether this device uses report IDs (any non-zero ReportID present for input buttons).
  bool hasReportIDs = false;
  std::unordered_set<UCHAR> validReportIDs; // for sanity checks
  for (USHORT i = 0; i < numBtnCaps; ++i) {
    const auto& bc = btnCaps[i];
    if (bc.UsagePage != HID_USAGE_PAGE_BUTTON) continue;
    validReportIDs.insert(static_cast<UCHAR>(bc.ReportID));
    if (bc.ReportID != 0) hasReportIDs = true;
    if (g_debug) {
      dbg_printf("[WinHID]   Cap[%u]: ReportID=%u UsagePage=%u LinkCollection=%u IsRange=%u",
                 (unsigned)i, bc.ReportID, bc.UsagePage, bc.LinkCollection, (unsigned)bc.IsRange);
    }
  }

  std::vector<BYTE> report(caps.InputReportByteLength);

  // Maintain last state per "logical" report id. If no report IDs, the key is 0.
  std::unordered_map<UCHAR, std::vector<BYTE>> lastById;

  OVERLAPPED ov{};
  ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!ov.hEvent) {
    dbg_printf("[WinHID] RunReader: CreateEventW failed: %s", last_error_str().c_str());
    HidD_FreePreparsedData(prep);
    return;
  }

  // Helper: compute the applicable ReportID for a given buffer.
  auto getRid = [&](const std::vector<BYTE>& src) -> UCHAR {
    if (!hasReportIDs) return 0;                 // no ID byte in buffer
    if (src.empty()) return 0;
    return src[0];                               // first byte is ReportID
  };

  // Parse pressed button usages from a specific buffer.
  auto collectUsages = [&](const std::vector<BYTE>& src,
                           std::unordered_set<USHORT>& out){
    if (src.empty()) return;
    UCHAR rid = getRid(src);

    // If device uses IDs, skip packets with unknown IDs.
    if (hasReportIDs && !validReportIDs.empty() && !validReportIDs.count(rid)) {
      if (g_debug) dbg_printf("[WinHID] RunReader: skip unknown ReportID=%u", rid);
      return;
    }

    for (USHORT i = 0; i < numBtnCaps; ++i) {
      const auto& bc = btnCaps[i];
      if (bc.UsagePage != HID_USAGE_PAGE_BUTTON) continue;

      // Only parse caps that match the current packet's ReportID.
      if (bc.ReportID != rid) continue;

      ULONG cnt = HidP_MaxUsageListLength(HidP_Input, bc.UsagePage, prep);
      if (cnt == 0) continue;
      std::vector<USAGE> usages(cnt);

      NTSTATUS s = HidP_GetUsages(
        HidP_Input,
        bc.UsagePage,
        bc.LinkCollection,
        usages.data(),
        &cnt,
        prep,
        (PCHAR)src.data(),
        (ULONG)src.size()
      );
      if (s == HIDP_STATUS_SUCCESS && cnt > 0) {
        for (ULONG k = 0; k < cnt; ++k) out.insert((USHORT)usages[k]);
      } else if (g_debug) {
        dbg_printf("[WinHID] RunReader: HidP_GetUsages failed rid=%u page=%u lc=%u: st=0x%08X",
                   rid, bc.UsagePage, bc.LinkCollection, (unsigned)s);
      }
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
        if (wait == WAIT_OBJECT_0) {
          GetOverlappedResult(L->handle, &ov, &bytesRead, FALSE);
        } else if (wait == WAIT_TIMEOUT) {
          continue;
        } else {
          dbg_printf("[WinHID] RunReader: WaitForSingleObject error: %s", last_error_str(wait).c_str());
          break;
        }
      } else {
        dbg_printf("[WinHID] RunReader: ReadFile error: %s", last_error_str(err).c_str());
        break;
      }
    } else {
      GetOverlappedResult(L->handle, &ov, &bytesRead, TRUE);
    }
    if (bytesRead == 0) continue;

    // Determine logical report id for diffing.
    UCHAR rid = getRid(report);

    std::unordered_set<USHORT> pressed, prevPressed;
    collectUsages(report, pressed);

    auto& prevBuf = lastById[rid];         // creates empty if first time
    if (!prevBuf.empty()) collectUsages(prevBuf, prevPressed);

    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();

    // Emits for presses
    for (auto u : pressed) {
      if (!prevPressed.count(u)) {
        if (g_debug) dbg_printf("[WinHID] Emit press: usage=%u rid=%u", u, rid);
        L->tsfn.BlockingCall([L, u, now](Napi::Env env, Napi::Function cb){
          Napi::Object evt = Napi::Object::New(env);
          evt.Set("path", Napi::String::New(env, WinHID::WToU8(L->pathW)));
          evt.Set("usagePage", Napi::Number::New(env, L->usagePage));
          evt.Set("usage", Napi::Number::New(env, L->usage));
          evt.Set("button", Napi::Number::New(env, u));
          evt.Set("pressed", Napi::Boolean::New(env, true));
          evt.Set("timestamp", Napi::Number::New(env, (double)now));
          cb.Call({ evt });
        });
      }
    }
    // Emits for releases
    for (auto u : prevPressed) {
      if (!pressed.count(u)) {
        if (g_debug) dbg_printf("[WinHID] Emit release: usage=%u rid=%u", u, rid);
        L->tsfn.BlockingCall([L, u, now](Napi::Env env, Napi::Function cb){
          Napi::Object evt = Napi::Object::New(env);
          evt.Set("path", Napi::String::New(env, WinHID::WToU8(L->pathW)));
          evt.Set("usagePage", Napi::Number::New(env, L->usagePage));
          evt.Set("usage", Napi::Number::New(env, L->usage));
          evt.Set("button", Napi::Number::New(env, u));
          evt.Set("pressed", Napi::Boolean::New(env, false));
          evt.Set("timestamp", Napi::Number::New(env, (double)now));
          cb.Call({ evt });
        });
      }
    }

    // Store last buffer for this logical ReportID
    prevBuf = report;
  }

  if (ov.hEvent) CloseHandle(ov.hEvent);
  HidD_FreePreparsedData(prep);
  dbg_printf("[WinHID] RunReader: exiting for %s", wstr_to_utf8(L->pathW).c_str());
}

// ---------- API: start/stop ----------
Napi::Value WinHID::StartListening(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  // Args: (filter?, callback)
  int cbIndex = (info.Length() >= 1 && info[0].IsFunction()) ? 0 : 1;
  if (info.Length() <= cbIndex || !info[cbIndex].IsFunction()) {
    Napi::TypeError::New(env, "callback function is required").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  Napi::Function cb = info[cbIndex].As<Napi::Function>();

  USHORT wantVid = 0, wantPid = 0, wantUsagePage = 0, wantUsage = 0;
  if (cbIndex == 1 && info[0].IsObject()) {
    Napi::Object f = info[0].As<Napi::Object>();
    if (f.Has("vendorId"))   wantVid = (USHORT)f.Get("vendorId").ToNumber().Uint32Value();
    if (f.Has("productId"))  wantPid = (USHORT)f.Get("productId").ToNumber().Uint32Value();
    if (f.Has("usagePage"))  wantUsagePage = (USHORT)f.Get("usagePage").ToNumber().Uint32Value();
    if (f.Has("usage"))      wantUsage = (USHORT)f.Get("usage").ToNumber().Uint32Value();
  }
  dbg_printf("[WinHID] StartListening: filter VID=0x%04X PID=0x%04X Page=%u Usage=%u",
             wantVid, wantPid, wantUsagePage, wantUsage);

  GUID hidGuid; HidD_GetHidGuid(&hidGuid);
  HDEVINFO devInfo = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
  if (devInfo == INVALID_HANDLE_VALUE) {
    Napi::Error::New(env, "SetupDiGetClassDevs failed").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  DWORD index = 0;
  SP_DEVICE_INTERFACE_DATA ifData; ifData.cbSize = sizeof(ifData);

  while (SetupDiEnumDeviceInterfaces(devInfo, nullptr, &hidGuid, index, &ifData)) {
    ++index;
    DWORD requiredSize = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, nullptr, 0, &requiredSize, nullptr);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0) {
      dbg_printf("[WinHID] StartListening: detail size query failed at idx=%lu: %s", index-1, last_error_str().c_str());
      continue;
    }
    std::vector<BYTE> buffer(requiredSize);
    auto detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    SP_DEVINFO_DATA devData; devData.cbSize = sizeof(devData);
    if (!SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, requiredSize, nullptr, &devData)) {
      dbg_printf("[WinHID] StartListening: GetDeviceInterfaceDetail failed idx=%lu: %s", index-1, last_error_str().c_str());
      continue;
    }

    std::wstring pathW(detail->DevicePath);
    std::string pathU8 = wstr_to_utf8(pathW);
    HANDLE h = INVALID_HANDLE_VALUE;
    if (!OpenHid(pathW, h)) {
      dbg_printf("[WinHID] StartListening: OpenHid failed for %s", pathU8.c_str());
      continue;
    }

    // best effort enlarge device queue
    if (!HidD_SetNumInputBuffers(h, 64)) {
      if (g_debug) dbg_printf("[WinHID] StartListening: HidD_SetNumInputBuffers failed (non-fatal): %s", last_error_str().c_str());
    }

    bool pass = true;
    if (wantVid || wantPid) {
      HIDD_ATTRIBUTES attrs; attrs.Size = sizeof(attrs);
      if (HidD_GetAttributes(h, &attrs)) {
        dbg_printf("[WinHID] Device %s VID=0x%04X PID=0x%04X", pathU8.c_str(), attrs.VendorID, attrs.ProductID);
        if (wantVid && attrs.VendorID != wantVid) pass = false;
        if (wantPid && attrs.ProductID != wantPid) pass = false;
      } else {
        dbg_printf("[WinHID] StartListening: HidD_GetAttributes failed for %s", pathU8.c_str());
      }
    }
    USHORT usagePage=0, usage=0, inLen=0;
    if (pass) pass = GetCaps(h, usagePage, usage, inLen);
    if (pass && wantUsagePage && usagePage != wantUsagePage) pass = false;
    if (pass && wantUsage && usage != wantUsage) pass = false;

    if (!pass) {
      dbg_printf("[WinHID] StartListening: filter rejected %s (Page=%u Usage=%u)", pathU8.c_str(), usagePage, usage);
      CloseHandle(h);
      continue;
    }

    auto L = std::make_shared<Listener>();
    L->pathW = pathW;
    L->handle = h;
    L->usagePage = usagePage;
    L->usage = usage;
    L->inputReportLen = inLen;
    L->prevReport.assign(inLen, 0); // legacy field; no longer used by RunReader

    L->tsfn = Napi::ThreadSafeFunction::New(env, cb, "hid-button-listener", 0, 1);

    std::string key = WToU8(pathW);
    dbg_printf("[WinHID] StartListening: starting reader for %s (Page=%u Usage=%u InLen=%u)",
               key.c_str(), usagePage, usage, inLen);
    L->th = std::thread([L]{ RunReader(L); });

    listeners_[key] = std::move(L);
  }

  SetupDiDestroyDeviceInfoList(devInfo);
  return env.Undefined();
}

void WinHID::stopAll() {
  dbg_printf("[WinHID] stopAll: stopping %zu listeners", listeners_.size());
  for (auto& kv : listeners_) {
    Listener* L = kv.second.get();
    if (!L) continue;
    L->stop.store(true);
    if (L->handle != INVALID_HANDLE_VALUE) {
      CancelIoEx(L->handle, nullptr);
    }
  }
  for (auto& kv : listeners_) {
    Listener* L = kv.second.get();
    if (!L) continue;
    if (L->th.joinable()) L->th.join();
    if (L->tsfn) { L->tsfn.Release(); }
    if (L->handle != INVALID_HANDLE_VALUE) {
      CloseHandle(L->handle);
      L->handle = INVALID_HANDLE_VALUE;
    }
  }
  listeners_.clear();
  dbg_printf("[WinHID] stopAll: done");
}

Napi::Value WinHID::StopListening(const Napi::CallbackInfo& info) {
  stopAll();
  return info.Env().Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    Napi::String name = Napi::String::New(env, "WinHID");
    exports.Set(name, WinHID::GetClass(env));
    return exports;
}

NODE_API_MODULE(addon, Init)

#endif
