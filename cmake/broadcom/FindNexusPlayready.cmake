# - Try to find Broadcom Nexus Playready.
# Once done this will define
#  NexusPlayready_FOUND     - System has a Nexus Playready
#  NexusPlayready::NexusPlayready - The Nexus Playready library
#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright (c) 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
find_path(LIBNexusPlayready_INCLUDE_DIR drmmanager.h
        PATH_SUFFIXES playready refsw)

find_path(LIBNexusSVP_INCLUDE_DIR sage_srai.h
        PATH_SUFFIXES refsw)

list(APPEND LIBNexusPlayready_INCLUDE_DIRS ${LIBNexusPlayready_INCLUDE_DIR} ${LIBNexusSVP_INCLUDE_DIR})

# main lib
find_library(LIBNexusPlayready_LIBRARY playready30pk)

# needed libs
list(APPEND NeededLibs prdyhttp)

# needed svp libs
list(APPEND NeededLibs drmrootfs srai)

foreach (_library ${NeededLibs})
    find_library(LIBRARY_${_library} ${_library})

    if(NOT EXISTS "${LIBRARY_${_library}}")
        message(SEND_ERROR "Could not find mandatory library: ${_library}")
    endif()

    list(APPEND LIBNexusPlayready_LIBRARIES ${LIBRARY_${_library}})

endforeach ()

if(EXISTS "${LIBNexusPlayready_LIBRARY}")
    include(FindPackageHandleStandardArgs)
    set(NexusPlayready_FOUND TRUE)

    find_package_handle_standard_args(LIBNexusPlayready DEFAULT_MSG LIBNEXUS_INCLUDE LIBNexusPlayready_LIBRARY)

    mark_as_advanced(LIBNexusPlayready_LIBRARY)

    if(NOT TARGET NexusPlayready::NexusPlayready)
        add_library(NexusPlayready::NexusPlayready UNKNOWN IMPORTED)
        
        set_target_properties(NexusPlayready::NexusPlayready PROPERTIES
                IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                IMPORTED_LOCATION "${LIBNexusPlayready_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBNexusPlayready_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${LIBNexusPlayready_LIBRARIES}"
                )
    endif()

endif()
