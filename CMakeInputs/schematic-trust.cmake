set(DIR_ENCODE "${DIR_NDN_LITE}/encode")
set(DIR_SCHEMA "${DIR_NDN_LITE}/encode/trust-schema")
set(DIR_UTIL "${DIR_NDN_LITE}/util")
set(DIR_SECURITY "${DIR_NDN_LITE}/security")
target_sources(ndn-lite PUBLIC
  ${DIR_ENCODE}/ndn-rule-storage.h
  ${DIR_SCHEMA}/ndn-trust-schema-common.h
  ${DIR_SCHEMA}/ndn-trust-schema-pattern-component.h
  ${DIR_SCHEMA}/ndn-trust-schema-pattern.h
  ${DIR_SCHEMA}/ndn-trust-schema-rule.h
  ${DIR_SECURITY}/ndn-trust-schema.h
  ${DIR_UTIL}/re.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_ENCODE}/ndn-rule-storage.c
  ${DIR_SCHEMA}/ndn-trust-schema-pattern-component.c
  ${DIR_SCHEMA}/ndn-trust-schema-pattern.c
  ${DIR_SCHEMA}/ndn-trust-schema-rule.c
  ${DIR_SECURITY}/ndn-trust-schema.c
  ${DIR_UTIL}/re.c
)
unset(DIR_SECURITY)
unset(DIR_UTIL)
unset(DIR_SCHEMA)
unset(DIR_ENCODE)