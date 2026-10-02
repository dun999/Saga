# Embeds a file as a string_view in the requested namespace (web assets by default).
if(NOT DEFINED NAMESPACE)
  set(NAMESPACE saga::web)
endif()
file(READ ${IN} CONTENT HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," BYTES "${CONTENT}")
file(WRITE ${OUT} "#include <string_view>\nnamespace ${NAMESPACE} {\nstatic const unsigned char k${NAME}Data[] = {${BYTES}};\nextern const std::string_view ${NAME}{reinterpret_cast<const char*>(k${NAME}Data), sizeof(k${NAME}Data)};\n}\n")
