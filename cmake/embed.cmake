# Turns a text file into a C++ translation unit exposing `saga::web::<NAME>` as a string_view.
file(READ ${IN} CONTENT HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," BYTES "${CONTENT}")
file(WRITE ${OUT} "#include <string_view>\nnamespace saga::web {\nstatic const unsigned char k${NAME}Data[] = {${BYTES}};\nextern const std::string_view ${NAME}{reinterpret_cast<const char*>(k${NAME}Data), sizeof(k${NAME}Data)};\n}\n")
