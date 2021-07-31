/*
 * Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if __GNUC__ < 4
#error "gcc version >= 4 is required"
#elif __GNUC__ == 4 && __GNUC_MINOR__ >= 6
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#elif __GNUC_MINOR__ >= 4
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

#include "topt.c"
