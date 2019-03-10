set(DIR_EXAMPLES_OUTPUT "${PROJECT_BINARY_DIR}/examples")

# Single-file examples
set(LIST_EXAMPLES
  "udp-basic-producer"
  "udp-basic-consumer"
  "udp-group-producer"
  "udp-group-consumer"
  "access-control-producer"
  "access-control-consumer"
  "access-control-controller"
  "time-server"
  "time-consumer"
  "print_consumer"
  "print_producer"
)
foreach(EXAM_NAME IN LISTS LIST_EXAMPLES)
  add_executable(${EXAM_NAME} "${DIR_EXAMPLES}/${EXAM_NAME}.c")
  target_link_libraries(${EXAM_NAME} ndn-lite)
  set_target_properties(${EXAM_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${DIR_EXAMPLES_OUTPUT})
endforeach()
unset(LIST_EXAMPLES)

target_sources(print_producer PRIVATE
  ${DIR_EXAMPLES}/yu-prnt-cmd-chk.c
  ${DIR_EXAMPLES}/yu-prnt-cmd-chk.h
)

unset(DIR_EXAMPLES_OUTPUT)
