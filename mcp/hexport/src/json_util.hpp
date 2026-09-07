// Thin helpers over the SDK's parsejson (jvalue_t/jobj_t/jarr_t). No external JSON
// library - the IDA SDK ships a full parser+serializer, so hexport stays self-contained.
#pragma once
#include "pch.h"

// --- reading ---------------------------------------------------------------
inline qstring jstr(const jobj_t &o, const char *k, const char *dflt = "")
{
  const jvalue_t *v = o.get_value(k, JT_STR);
  return v != nullptr ? v->qstr() : qstring(dflt);
}

inline int64 jint(const jobj_t &o, const char *k, int64 dflt = 0)
{
  const jvalue_t *v = o.get_value(k, JT_NUM);
  return v != nullptr ? v->num() : dflt;
}

inline const jobj_t *jsub(const jobj_t &o, const char *k)
{
  const jvalue_t *v = o.get_value(k, JT_OBJ);
  return v != nullptr ? &v->obj() : nullptr;
}

inline const jarr_t *jsubarr(const jobj_t &o, const char *k)
{
  const jvalue_t *v = o.get_value(k, JT_ARR);
  return v != nullptr ? &v->arr() : nullptr;
}

// Move an owned value into obj[key] (parsejson's put() only covers leaf types).
inline void jput(jobj_t &o, const char *k, jvalue_t &v)
{
  o.get_value_or_new(k)->swap(v);
}

// --- (de)serialization -----------------------------------------------------
inline qstring jdump(const jobj_t &o)
{
  qstring out;
  serialize_json(&out, &o, 0);   // flags=0 -> compact, single line
  return out;
}

inline bool jparse(const char *s, jvalue_t *out)
{
  qstring err;
  return parse_json_string(out, s, &err) == 0;   // error_t 0 == success
}
