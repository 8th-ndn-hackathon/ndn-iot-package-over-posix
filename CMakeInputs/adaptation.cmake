set(DIR_UDP_UNICAST "${DIR_ADAPTATION}/udp-unicast")
target_sources(ndn-lite PUBLIC
  ${DIR_UDP_UNICAST}/ndn-udp-unicast-face.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_UDP_UNICAST}/ndn-udp-unicast-face.c
)
unset(DIR_UDP_UNICAST)

set(DIR_UDP_MULTICAST "${DIR_ADAPTATION}/udp-multicast")
target_sources(ndn-lite PUBLIC
  ${DIR_UDP_MULTICAST}/ndn-udp-multicast-face.h
)
target_sources(ndn-lite PRIVATE
  ${DIR_UDP_MULTICAST}/ndn-udp-multicast-face.c
)
unset(DIR_UDP_MULTICAST)
