// Raw KUSER_SHARED_DATA clock. The kernel maps a read-only copy of _KUSER_SHARED_DATA into
// every process at the fixed user-mode address 0x7FFE0000, so reading the time from it is a
// plain memory load -- no syscall, no QueryPerformanceCounter, no <chrono>.
//
// Header-free: the only thing pulled in is our own kstl::string; the fixed-width layout types
// are hand-written typedefs (not `using`, not the SDK's, so no collision), and the offset
// checks use __builtin_offsetof -- no <cstdint>/<cstddef>/<string>. Layout is the x64
// Windows 10 22H2 _KUSER_SHARED_DATA
// (https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_KUSER_SHARED_DATA); the
// static_asserts pin sizeof and every offset, so it is provably correct.
#pragma once
#include "kstl/string.hpp"

namespace kuser {

// Fixed-width layout types, written by hand (Windows-header style typedefs, our own names).
typedef unsigned char      u8;    // 1
typedef unsigned short     u16;   // 2
typedef unsigned int       u32;   // 4
typedef unsigned long long u64;   // 8
typedef int                i32;   // 4
typedef long long          i64;   // 8

struct _KSYSTEM_TIME
{
  u32 LowPart;
  i32 High1Time;
  i32 High2Time;
};

union _LARGE_INTEGER
{
  struct { u32 LowPart; i32 HighPart; };
  struct { u32 LowPart; i32 HighPart; } u;
  i64 QuadPart;
};

enum _ALTERNATIVE_ARCHITECTURE_TYPE { StandardDesign = 0, NEC98x86 = 1, EndAlternatives = 2 };
enum _NT_PRODUCT_TYPE { NtProductWinNt = 1, NtProductLanManNt = 2, NtProductServer = 3 };

struct _XSTATE_FEATURE
{
  u32 Offset;
  u32 Size;
};

struct _XSTATE_CONFIGURATION
{
  u64 EnabledFeatures;                                 // 0x000
  u64 EnabledVolatileFeatures;                         // 0x008
  u32 Size;                                            // 0x010
  union                                                // 0x014
  {
    u32 ControlFlags;
    struct
    {
      u32 OptimizedSave : 1;
      u32 CompactionEnabled : 1;
    };
  };
  _XSTATE_FEATURE Features[64];                         // 0x018
  u64 EnabledSupervisorFeatures;                       // 0x218
  u64 AlignedFeatures;                                 // 0x220
  u32 AllFeatureSize;                                  // 0x228
  u32 AllFeatures[64];                                 // 0x22c
  u64 EnabledUserVisibleSupervisorFeatures;            // 0x330
};
static_assert(sizeof(_XSTATE_CONFIGURATION) == 0x338, "XSTATE_CONFIGURATION size");

struct _KUSER_SHARED_DATA
{
  u32 TickCountLowDeprecated;                          // 0x000
  u32 TickCountMultiplier;                             // 0x004
  volatile _KSYSTEM_TIME InterruptTime;                // 0x008  monotonic 100ns tick
  volatile _KSYSTEM_TIME SystemTime;                   // 0x014  wall clock (can jump)
  volatile _KSYSTEM_TIME TimeZoneBias;                 // 0x020
  u16 ImageNumberLow;                                  // 0x02c
  u16 ImageNumberHigh;                                 // 0x02e
  u16 NtSystemRoot[260];                               // 0x030  (WCHAR)
  u32 MaxStackTraceDepth;                              // 0x238
  u32 CryptoExponent;                                  // 0x23c
  u32 TimeZoneId;                                      // 0x240
  u32 LargePageMinimum;                                // 0x244
  u32 AitSamplingValue;                                // 0x248
  u32 AppCompatFlag;                                   // 0x24c
  u64 RNGSeedVersion;                                  // 0x250
  u32 GlobalValidationRunlevel;                        // 0x258
  volatile i32 TimeZoneBiasStamp;                      // 0x25c
  u32 NtBuildNumber;                                   // 0x260
  _NT_PRODUCT_TYPE NtProductType;                      // 0x264
  u8 ProductTypeIsValid;                               // 0x268
  u8 Reserved0[1];                                     // 0x269
  u16 NativeProcessorArchitecture;                     // 0x26a
  u32 NtMajorVersion;                                  // 0x26c
  u32 NtMinorVersion;                                  // 0x270
  u8 ProcessorFeatures[64];                            // 0x274
  u32 Reserved1;                                       // 0x2b4
  u32 Reserved3;                                       // 0x2b8
  volatile u32 TimeSlip;                               // 0x2bc
  _ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture; // 0x2c0
  u32 BootId;                                          // 0x2c4
  _LARGE_INTEGER SystemExpirationDate;                 // 0x2c8
  u32 SuiteMask;                                       // 0x2d0
  u8 KdDebuggerEnabled;                                // 0x2d4
  union                                                // 0x2d5
  {
    u8 MitigationPolicies;
    struct
    {
      u8 NXSupportPolicy : 2;
      u8 SEHValidationPolicy : 2;
      u8 CurDirDevicesSkippedForDlls : 2;
      u8 Reserved : 2;
    };
  };
  u16 CyclesPerYield;                                  // 0x2d6
  volatile u32 ActiveConsoleId;                        // 0x2d8
  volatile u32 DismountCount;                          // 0x2dc
  u32 ComPlusPackage;                                  // 0x2e0
  u32 LastSystemRITEventTickCount;                     // 0x2e4
  u32 NumberOfPhysicalPages;                           // 0x2e8
  u8 SafeBootMode;                                     // 0x2ec
  u8 VirtualizationFlags;                              // 0x2ed
  u8 Reserved12[2];                                    // 0x2ee
  union                                                // 0x2f0
  {
    u32 SharedDataFlags;
    struct
    {
      u32 DbgErrorPortPresent : 1;
      u32 DbgElevationEnabled : 1;
      u32 DbgVirtEnabled : 1;
      u32 DbgInstallerDetectEnabled : 1;
      u32 DbgLkgEnabled : 1;
      u32 DbgDynProcessorEnabled : 1;
      u32 DbgConsoleBrokerEnabled : 1;
      u32 DbgSecureBootEnabled : 1;
      u32 DbgMultiSessionSku : 1;
      u32 DbgMultiUsersInSessionSku : 1;
      u32 DbgStateSeparationEnabled : 1;
      u32 SpareBits : 21;
    };
  };
  u32 DataFlagsPad[1];                                 // 0x2f4
  u64 TestRetInstruction;                              // 0x2f8
  i64 QpcFrequency;                                    // 0x300
  u32 SystemCall;                                      // 0x308
  u32 Reserved2;                                       // 0x30c
  u64 SystemCallPad[2];                                // 0x310
  union                                                // 0x320
  {
    volatile _KSYSTEM_TIME TickCount;
    volatile u64 TickCountQuad;                        // forces 8-byte align -> union is 16 bytes
    struct
    {
      u32 ReservedTickCountOverlay[3];
      u32 TickCountPad[1];                             // 0x32c, inside the union overlay
    };
  };
  u32 Cookie;                                          // 0x330
  u32 CookiePad[1];                                    // 0x334
  i64 ConsoleSessionForegroundProcessId;               // 0x338
  u64 TimeUpdateLock;                                  // 0x340
  u64 BaselineSystemTimeQpc;                           // 0x348
  u64 BaselineInterruptTimeQpc;                        // 0x350
  u64 QpcSystemTimeIncrement;                          // 0x358
  u64 QpcInterruptTimeIncrement;                       // 0x360
  u8 QpcSystemTimeIncrementShift;                      // 0x368
  u8 QpcInterruptTimeIncrementShift;                   // 0x369
  u16 UnparkedProcessorCount;                          // 0x36a
  u32 EnclaveFeatureMask[4];                           // 0x36c
  u32 TelemetryCoverageRound;                          // 0x37c
  u16 UserModeGlobalLogger[16];                        // 0x380
  u32 ImageFileExecutionOptions;                       // 0x3a0
  u32 LangGenerationCount;                             // 0x3a4
  u64 Reserved4;                                       // 0x3a8
  volatile u64 InterruptTimeBias;                      // 0x3b0
  volatile u64 QpcBias;                                // 0x3b8
  u32 ActiveProcessorCount;                            // 0x3c0
  volatile u8 ActiveGroupCount;                        // 0x3c4
  u8 Reserved9;                                        // 0x3c5
  union                                                // 0x3c6
  {
    u16 QpcData;
    struct
    {
      volatile u8 QpcBypassEnabled;
      u8 QpcShift;
    };
  };
  _LARGE_INTEGER TimeZoneBiasEffectiveStart;           // 0x3c8
  _LARGE_INTEGER TimeZoneBiasEffectiveEnd;             // 0x3d0
  _XSTATE_CONFIGURATION XState;                        // 0x3d8
  _KSYSTEM_TIME FeatureConfigurationChangeStamp;       // 0x710
  u32 Spare;                                           // 0x71c
};

static_assert(sizeof(_KSYSTEM_TIME) == 0x0C, "KSYSTEM_TIME size");
static_assert(sizeof(_KUSER_SHARED_DATA) == 0x720, "KUSER_SHARED_DATA size");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, InterruptTime) == 0x08, "InterruptTime offset");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, SystemTime) == 0x14, "SystemTime offset");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, QpcFrequency) == 0x300, "QpcFrequency offset");
static_assert(__builtin_offsetof(_KUSER_SHARED_DATA, TickCount) == 0x320, "TickCount offset");

// The kernel maps _KUSER_SHARED_DATA read-only at this fixed user-mode address. Resolve the
// pointer ONCE here (inline global, one definition across TUs) instead of re-casting on every
// access; all accessors read through KUSD.
inline const _KUSER_SHARED_DATA *const KUSD =
    reinterpret_cast<const _KUSER_SHARED_DATA *>(0x7FFE0000ull);

// Singleton over the shared page. Accessors are split into small nested classes by domain, so
// you reach one as:
//
//     KUser::get_instance().datetime.get_year()
//     KUser::get_instance().clock.seconds()
//     KUser::get_instance().os.version_string()
//
// That keeps get_instance() itself tiny instead of exposing every field as a flat method. Each
// group is a stateless handle; every read goes straight through KUSD -- no QPC, no syscall.
class KUser
{
public:
  KUser(const KUser &) = delete;
  KUser &operator=(const KUser &) = delete;

  static KUser &get_instance()
  {
    static KUser instance;   // thread-safe init (C++11+); the mapping is process-wide
    return instance;
  }

  // Broken-down calendar time, returned by the DateTime group's now_utc()/now_local().
  struct Timestamp
  {
    int year;
    unsigned month;        // 1-12
    unsigned day;          // 1-31
    unsigned hour;         // 0-23
    unsigned minute;       // 0-59
    unsigned second;       // 0-59
    unsigned millisecond;  // 0-999
    unsigned weekday;      // 0=Sunday .. 6=Saturday
  };

  // ---- monotonic time: get_instance().clock.<method>() ----
  // The right source for elapsed/duration -- never jumps.
  struct Clock
  {
    u64 interrupt_time_100ns() const
    {
      return read_ksystime(&KUSD->InterruptTime);
    }

    u64 interrupt_time_ns() const   // nanoseconds since boot
    {
      return interrupt_time_100ns() * 100;
    }

    double seconds() const   // since boot
    {
      return double(interrupt_time_100ns()) * 1e-7;
    }

    u64 uptime_ms() const   // since boot
    {
      return interrupt_time_100ns() / 10000;
    }

    kstl::string uptime_string() const   // "5d 07h 08m 16s"
    {
      u64 s = interrupt_time_100ns() / 10000000ull;
      kstl::string out;
      append_num(out, unsigned(s / 86400), 1);
      out.append("d ");
      append_num(out, unsigned((s % 86400) / 3600), 2);
      out.append("h ");
      append_num(out, unsigned((s % 3600) / 60), 2);
      out.append("m ");
      append_num(out, unsigned(s % 60), 2);
      out.push_back('s');
      return out;
    }

    u64 interrupt_time_bias() const
    {
      return KUSD->InterruptTimeBias;
    }

    u64 tick_count() const
    {
      return KUSD->TickCountQuad;
    }

    u32 tick_count_multiplier() const
    {
      return KUSD->TickCountMultiplier;
    }

    i64 qpc_frequency() const
    {
      return KUSD->QpcFrequency;
    }

    u64 qpc_bias() const
    {
      return KUSD->QpcBias;
    }

    bool qpc_bypass_enabled() const
    {
      return KUSD->QpcBypassEnabled != 0;
    }
  } clock;

  // ---- wall clock + calendar: get_instance().datetime.<method>() ----
  // Time of day; can jump on NTP/DST -- never use for durations.
  struct DateTime
  {
    u64 system_time_100ns() const   // 100ns since 1601-01-01 (FILETIME epoch)
    {
      return read_ksystime(&KUSD->SystemTime);
    }

    double unix_time() const   // seconds since 1970-01-01
    {
      return double(system_time_100ns() - 116444736000000000ull) * 1e-7;
    }

    u64 unix_time_ms() const   // milliseconds since 1970-01-01
    {
      return (system_time_100ns() - 116444736000000000ull) / 10000;
    }

    u64 time_zone_bias_100ns() const
    {
      return read_ksystime(&KUSD->TimeZoneBias);
    }

    u32 time_zone_id() const
    {
      return KUSD->TimeZoneId;
    }

    Timestamp now_utc() const
    {
      return to_datetime(system_time_100ns());
    }

    Timestamp now_local() const   // UTC minus the current TZ (+DST) bias
    {
      return to_datetime(system_time_100ns() - time_zone_bias_100ns());
    }

    int get_year() const
    {
      return now_utc().year;
    }

    unsigned get_month() const
    {
      return now_utc().month;
    }

    unsigned get_day() const
    {
      return now_utc().day;
    }

    unsigned get_hour() const
    {
      return now_utc().hour;
    }

    unsigned get_minute() const
    {
      return now_utc().minute;
    }

    unsigned get_second() const
    {
      return now_utc().second;
    }

    unsigned get_millisecond() const
    {
      return now_utc().millisecond;
    }

    unsigned get_weekday() const
    {
      return now_utc().weekday;
    }

    unsigned day_of_year() const   // 1-366
    {
      Timestamp t = now_utc();
      static const unsigned cum[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
      unsigned doy = cum[(t.month >= 1 && t.month <= 12) ? t.month - 1 : 0] + t.day;
      bool leap = (t.year % 4 == 0 && t.year % 100 != 0) || (t.year % 400 == 0);
      if ( leap && t.month > 2 )
        doy += 1;
      return doy;
    }

    kstl::string weekday_name() const   // "Monday"
    {
      static const char *const names[7] =
        { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
      unsigned w = now_utc().weekday;
      return names[w < 7 ? w : 0];
    }

    kstl::string month_name() const   // "September"
    {
      static const char *const names[12] =
        { "January", "February", "March", "April", "May", "June",
          "July", "August", "September", "October", "November", "December" };
      unsigned m = now_utc().month;
      return names[(m >= 1 && m <= 12) ? m - 1 : 0];
    }

    kstl::string to_string() const         // "YYYY-MM-DD HH:MM:SS" (UTC)
    {
      return ymdhms(now_utc());
    }

    kstl::string to_string_local() const   // "YYYY-MM-DD HH:MM:SS" (wall-local)
    {
      return ymdhms(now_local());
    }

    kstl::string iso8601() const   // "2026-09-07T04:55:00.242Z" (UTC)
    {
      Timestamp t = now_utc();
      kstl::string s;
      append_num(s, unsigned(t.year), 4);
      s.push_back('-');
      append_num(s, t.month, 2);
      s.push_back('-');
      append_num(s, t.day, 2);
      s.push_back('T');
      append_num(s, t.hour, 2);
      s.push_back(':');
      append_num(s, t.minute, 2);
      s.push_back(':');
      append_num(s, t.second, 2);
      s.push_back('.');
      append_num(s, t.millisecond, 3);
      s.push_back('Z');
      return s;
    }
  } datetime;

  // ---- OS identity: get_instance().os.<method>() ----
  struct OsInfo
  {
    u32 build_number() const
    {
      return KUSD->NtBuildNumber;
    }

    u32 major_version() const
    {
      return KUSD->NtMajorVersion;
    }

    u32 minor_version() const
    {
      return KUSD->NtMinorVersion;
    }

    kstl::string version_string() const   // "10.0.19045"
    {
      kstl::string s;
      append_num(s, major_version(), 1);
      s.push_back('.');
      append_num(s, minor_version(), 1);
      s.push_back('.');
      append_num(s, build_number(), 1);
      return s;
    }

    _NT_PRODUCT_TYPE product_type() const
    {
      return KUSD->NtProductType;
    }

    kstl::string product_type_name() const
    {
      switch ( KUSD->NtProductType )
      {
        case NtProductWinNt:    return "Workstation";
        case NtProductLanManNt: return "Domain Controller";
        case NtProductServer:   return "Server";
        default:                return "Unknown";
      }
    }

    bool is_server() const
    {
      return KUSD->NtProductType != NtProductWinNt;
    }

    u16 processor_architecture() const
    {
      return KUSD->NativeProcessorArchitecture;
    }

    kstl::string processor_architecture_name() const
    {
      switch ( KUSD->NativeProcessorArchitecture )
      {
        case 0:  return "x86";
        case 5:  return "ARM";
        case 6:  return "IA64";
        case 9:  return "x64";
        case 12: return "ARM64";
        default: return "Unknown";
      }
    }

    u32 boot_id() const
    {
      return KUSD->BootId;
    }

    u32 suite_mask() const
    {
      return KUSD->SuiteMask;
    }

    kstl::string system_root() const   // "C:\Windows"
    {
      kstl::string s;
      for ( int i = 0; i < 260 && KUSD->NtSystemRoot[i] != 0; ++i )
        s.push_back(char(KUSD->NtSystemRoot[i]));   // system root is ASCII
      return s;
    }
  } os;

  // ---- hardware / CPU: get_instance().cpu.<method>() ----
  struct Cpu
  {
    u32 processor_count() const
    {
      return KUSD->ActiveProcessorCount;
    }

    unsigned active_group_count() const
    {
      return KUSD->ActiveGroupCount;
    }

    u16 unparked_processor_count() const
    {
      return KUSD->UnparkedProcessorCount;
    }

    u16 cycles_per_yield() const
    {
      return KUSD->CyclesPerYield;
    }

    u32 physical_pages() const
    {
      return KUSD->NumberOfPhysicalPages;
    }

    u64 physical_memory_bytes() const
    {
      return u64(KUSD->NumberOfPhysicalPages) * 4096ull;
    }

    u32 large_page_minimum() const
    {
      return KUSD->LargePageMinimum;
    }

    // A PF_* processor-feature flag (e.g. PF_XMMI64_INSTRUCTIONS_AVAILABLE); false if out of range.
    bool is_feature_present(unsigned feature) const
    {
      return feature < 64 && KUSD->ProcessorFeatures[feature] != 0;
    }

    bool has_sse2() const { return is_feature_present(10); }   // PF_XMMI64_INSTRUCTIONS_AVAILABLE
    bool has_sse3() const { return is_feature_present(13); }   // PF_SSE3_INSTRUCTIONS_AVAILABLE
    bool has_nx()   const { return is_feature_present(12); }   // PF_NX_ENABLED (DEP)
  } cpu;

  // ---- security / debug state: get_instance().security.<method>() ----
  struct Security
  {
    bool kd_debugger_enabled() const   // boot /DEBUG flag
    {
      return KUSD->KdDebuggerEnabled != 0;
    }

    bool safe_boot_mode() const
    {
      return KUSD->SafeBootMode != 0;
    }

    bool secure_boot_enabled() const
    {
      return KUSD->DbgSecureBootEnabled != 0;
    }

    bool dbg_elevation_enabled() const
    {
      return KUSD->DbgElevationEnabled != 0;
    }

    bool dbg_virt_enabled() const
    {
      return KUSD->DbgVirtEnabled != 0;
    }

    unsigned nx_support_policy() const    // 0=AlwaysOff 1=AlwaysOn 2=OptIn 3=OptOut
    {
      return KUSD->NXSupportPolicy;
    }

    unsigned seh_validation_policy() const
    {
      return KUSD->SEHValidationPolicy;
    }

    u32 shared_data_flags() const
    {
      return KUSD->SharedDataFlags;
    }

    u32 cookie() const   // SharedUserData cookie (pointer-encoding seed)
    {
      return KUSD->Cookie;
    }
  } security;

  // Raw page, for any field not wrapped by a group above.
  const _KUSER_SHARED_DATA *data() const
  {
    return KUSD;
  }

private:
  KUser() = default;

  // KSYSTEM_TIME is written by the kernel as three 32-bit fields, so re-read until the two
  // High words agree -- that rejects a torn value straddling a kernel update.
  static u64 read_ksystime(const volatile _KSYSTEM_TIME *time_ptr)
  {
    for ( ;; )
    {
      i32 high1 = time_ptr->High1Time;
      u32 low   = time_ptr->LowPart;
      i32 high2 = time_ptr->High2Time;
      if ( high1 == high2 )
        return (u64(u32(high1)) << 32) | low;
    }
  }

  // Civil calendar from a FILETIME (100ns since 1601-01-01 UTC). Pure arithmetic (Howard
  // Hinnant's days<->civil algorithm) -- no FileTimeToSystemTime, no kernel call.
  static Timestamp to_datetime(u64 filetime_100ns)
  {
    const u64 sec_1601 = filetime_100ns / 10000000ull;
    i64 unix_sec = i64(sec_1601) - 11644473600ll;   // 1601-01-01 -> 1970-01-01
    i64 days = unix_sec / 86400;
    i64 sod = unix_sec % 86400;
    if ( sod < 0 )   // floor toward -infinity (guards pre-1970 inputs)
    {
      sod += 86400;
      --days;
    }
    int y;
    unsigned mo, d;
    civil_from_days(days, y, mo, d);
    Timestamp dt = {};
    dt.year = y;
    dt.month = mo;
    dt.day = d;
    dt.hour = unsigned(sod / 3600);
    dt.minute = unsigned((sod % 3600) / 60);
    dt.second = unsigned(sod % 60);
    dt.millisecond = unsigned((filetime_100ns / 10000ull) % 1000ull);
    i64 wd = (days % 7 + 4) % 7;   // 1970-01-01 was a Thursday (=4)
    if ( wd < 0 )
      wd += 7;
    dt.weekday = unsigned(wd);
    return dt;
  }

  // days since 1970-01-01 -> civil (year, month [1,12], day [1,31]).
  static void civil_from_days(i64 z, int &y, unsigned &m, unsigned &d)
  {
    z += 719468;   // shift the epoch to 0000-03-01
    const i64 era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = unsigned(z - era * 146097);                            // [0, 146096]
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    const i64 yr = i64(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);               // [0, 365]
    const unsigned mp = (5 * doy + 2) / 153;                                    // [0, 11]
    d = doy - (153 * mp + 2) / 5 + 1;                                           // [1, 31]
    m = mp < 10 ? mp + 3 : mp - 9;                                              // [1, 12]
    y = int(yr) + (m <= 2);
  }

  // "YYYY-MM-DD HH:MM:SS" from a broken-down time.
  static kstl::string ymdhms(const Timestamp &t)
  {
    kstl::string s;
    append_num(s, unsigned(t.year), 4);
    s.push_back('-');
    append_num(s, t.month, 2);
    s.push_back('-');
    append_num(s, t.day, 2);
    s.push_back(' ');
    append_num(s, t.hour, 2);
    s.push_back(':');
    append_num(s, t.minute, 2);
    s.push_back(':');
    append_num(s, t.second, 2);
    return s;
  }

  // Append `value` to `s` as decimal digits, zero-padded to at least `width`.
  static void append_num(kstl::string &s, unsigned value, int width)
  {
    char buf[16];
    int n = 0;
    do
    {
      buf[n++] = char('0' + value % 10);
      value /= 10;
    } while ( value != 0 );
    for ( int i = n; i < width; ++i )
      s.push_back('0');
    while ( n > 0 )
      s.push_back(buf[--n]);
  }
};

}  // namespace kuser

using kuser::KUser;
