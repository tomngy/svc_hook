/**
 * @author      : wz 
 * @file        : logger
 * @created     : Wednesday Dec 07, 2022 11:30:16 CST
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

#ifdef DEBUG_
#define LOGD(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__) 
#define LOGE(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__) 
#else
#define LOGD(fmt, ...)
#define LOGE(fmt, ...)
#endif

#endif /* end of include guard LOGGER_H */

