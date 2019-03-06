// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_config.h"
#include "pal_threading.h"
#include "pal_utilities.h"

#include <stdlib.h>
#include <pthread.h>
#include <time.h>

struct Monitor
{
    pthread_mutex_t Mutex;
    pthread_cond_t Condition;
};

struct LifoSemaphoreWaitEntry
{
    pthread_cond_t Condition;
    int Signalled;
    struct LifoSemaphoreWaitEntry *Previous;
    struct LifoSemaphoreWaitEntry *Next;
};

struct LifoSemaphore
{
    pthread_mutex_t Mutex;
    struct LifoSemaphoreWaitEntry *Head;
    uint32_t PendingSignals;
};

enum
{
    SecondsToNanoSeconds = 1000000000, // 10^9
    MilliSecondsToNanoSeconds = 1000000 // 10^6
};

#ifdef NDEBUG
#define assert_no_error(err) ((void)(err))
#else
#define assert_no_error(err) assert((err) == 0)
#endif

static int pthread_cond_timedwait_relative_ms(pthread_cond_t *condition, pthread_mutex_t *mutex, int32_t timeoutMilliseconds)
{
    if (timeoutMilliseconds < 0)
    {
        return pthread_cond_wait(condition, mutex);
    }

    // Calculate the time at which a timeout should occur, and wait. Older versions of OSX don't support clock_gettime with
    // CLOCK_MONOTONIC, so we instead compute the relative timeout duration, and use a relative variant of the timed wait.
    struct timespec timeout;
#if HAVE_MACH_ABSOLUTE_TIME
    timeout.tv_sec = (time_t)(timeoutMilliseconds / 1000);
    timeout.tv_nsec = (long)((timeoutMilliseconds % 1000) * MilliSecondsToNanoSeconds);
    return pthread_cond_timedwait_relative_np(condition, mutex, &timeout);
#else
    uint64_t nanoseconds;
    int error = clock_gettime(CLOCK_MONOTONIC, &timeout);
    if (error == 0)
    {
        nanoseconds = ((uint64_t)timeout.tv_sec * SecondsToNanoSeconds) + (uint64_t)timeout.tv_nsec;
        nanoseconds += (uint64_t)timeoutMilliseconds * MilliSecondsToNanoSeconds;
        timeout.tv_sec = (time_t)(nanoseconds / SecondsToNanoSeconds);
        timeout.tv_nsec = (long)(nanoseconds % SecondsToNanoSeconds);
        error = pthread_cond_timedwait(condition, mutex, &timeout);
    }
    return error;
#endif
}

Monitor *SystemNative_MonitorNew(void)
{
    Monitor *monitor;
    int error, initError;

    monitor = (Monitor *)malloc(sizeof(struct Monitor));
    if (monitor == NULL)
    {
        return NULL;
    }

    error = pthread_mutex_init(&monitor->Mutex, NULL);
    if (error != 0)
    {
        free(monitor);
        return NULL;
    }

#if HAVE_MACH_ABSOLUTE_TIME
    // Older versions of OSX don't support CLOCK_MONOTONIC, so we don't use pthread_condattr_setclock. See
    // Wait(int32_t timeoutMilliseconds).
    initError = pthread_cond_init(&monitor->Condition, NULL);
#elif HAVE_PTHREAD_CONDATTR_SETCLOCK && HAVE_CLOCK_MONOTONIC
    pthread_condattr_t conditionAttributes;
    error = pthread_condattr_init(&conditionAttributes);
    if (error != 0)
    {
        error = pthread_mutex_destroy(&monitor->Mutex);
        assert_no_error(error);
        free(monitor);
        return NULL;
    }

    error = pthread_condattr_setclock(&conditionAttributes, CLOCK_MONOTONIC);
    assert_no_error(error);

    initError = pthread_cond_init(&monitor->Condition, &conditionAttributes);

    error = pthread_condattr_destroy(&conditionAttributes);
    assert_no_error(error);
#else
    #error "Don't know how to perform timed wait on this platform"
#endif

    if (initError != 0)
    {
        error = pthread_mutex_destroy(&monitor->Mutex);
        assert_no_error(error);
        free(monitor);
        return NULL;
    }

    return monitor;
}

void SystemNative_MonitorDelete(Monitor *monitor)
{
    int error;

    error = pthread_mutex_destroy(&monitor->Mutex);
    assert_no_error(error);
    error = pthread_cond_destroy(&monitor->Condition);
    assert_no_error(error);
    free(monitor);
}

void SystemNative_MonitorAcquire(Monitor *monitor)
{
    int error = pthread_mutex_lock(&monitor->Mutex);
    assert_no_error(error);
}

void SystemNative_MonitorRelease(Monitor *monitor)
{
    int error = pthread_mutex_unlock(&monitor->Mutex);
    assert_no_error(error);
}

int32_t SystemNative_MonitorTimedWait(Monitor *monitor, int32_t timeoutMilliseconds)
{
    assert(timeoutMilliseconds >= -1);
    int error = pthread_cond_timedwait_relative_ms(&monitor->Condition, &monitor->Mutex, timeoutMilliseconds);
    assert(error == 0 || error == ETIMEDOUT);
    return error == 0;
}

void SystemNative_MonitorSignalAndRelease(Monitor *monitor)
{
    int error = pthread_cond_signal(&monitor->Condition);
    assert_no_error(error);
    SystemNative_MonitorRelease(monitor);
}

DLLEXPORT LifoSemaphore *SystemNative_LifoSemaphoreNew(void)
{
    LifoSemaphore *semaphore;
    int error;

    semaphore = (LifoSemaphore *)malloc(sizeof(struct LifoSemaphore));
    if (semaphore == NULL)
    {
        return NULL;
    }

    error = pthread_mutex_init(&semaphore->Mutex, NULL);
    if (error != 0)
    {
        free(semaphore);
        return NULL;
    }

    return semaphore;
}

DLLEXPORT void SystemNative_LifoSemaphoreDelete(LifoSemaphore *semaphore)
{
    int error;

    assert(semaphore->Head == NULL);
    error = pthread_mutex_destroy(&semaphore->Mutex);
    assert_no_error(error);
    free(semaphore);
}

DLLEXPORT int32_t SystemNative_LifoSemaphoreTimedWait(LifoSemaphore *semaphore, int32_t timeoutMilliseconds)
{
    int error;
    // FIXME: Set correct clock
    struct LifoSemaphoreWaitEntry waitEntry = { PTHREAD_COND_INITIALIZER, 0, NULL, NULL };

    error = pthread_mutex_lock(&semaphore->Mutex);
    assert_no_error(error);

    if (semaphore->PendingSignals > 0)
    {
        --semaphore->PendingSignals;
        error = pthread_mutex_unlock(&semaphore->Mutex);
        assert_no_error(error);
        return 1;
    }

    // Enqueue out entry into the LIFO wait list
    waitEntry.Previous = NULL;
    waitEntry.Next = semaphore->Head;
    if (semaphore->Head != NULL)
        semaphore->Head->Previous = &waitEntry;
    semaphore->Head = &waitEntry;

    // Wait for a signal or timeout
    int waitError = 0;
    do
    {
        waitError = pthread_cond_timedwait_relative_ms(&waitEntry.Condition, &semaphore->Mutex, timeoutMilliseconds);
        assert(waitError == 0 || waitError == ETIMEDOUT);
    }
    while (waitError == 0 && !waitEntry.Signalled);

    if (waitError == ETIMEDOUT)
    {
        if (semaphore->Head == &waitEntry)
            semaphore->Head = waitEntry.Next;
        if (waitEntry.Next != NULL)
            waitEntry.Next->Previous = waitEntry.Previous;
        if (waitEntry.Previous != NULL)
            waitEntry.Previous->Next = waitEntry.Next;
    }

    error = pthread_cond_destroy(&waitEntry.Condition);
    assert_no_error(error);
    error = pthread_mutex_unlock(&semaphore->Mutex);
    assert_no_error(error);

    return waitEntry.Signalled;
}

DLLEXPORT void SystemNative_LifoSemaphoreRelease(LifoSemaphore *semaphore, uint32_t count)
{
    int error;

    error = pthread_mutex_lock(&semaphore->Mutex);
    assert_no_error(error);
    while (count > 0)
    {
        // Dequeue entries from the LIFO wait list and signal them
        struct LifoSemaphoreWaitEntry *waitEntry = semaphore->Head;
        if (waitEntry != NULL)
        {
            semaphore->Head = waitEntry->Next;
            if (semaphore->Head != NULL)
                semaphore->Head->Previous = NULL;
            waitEntry->Previous = NULL;
            waitEntry->Next = NULL;
            waitEntry->Signalled = 1;
            error = pthread_cond_signal(&waitEntry->Condition);
            assert_no_error(error);
            --count;
        }
        else
        {
            semaphore->PendingSignals += count;
            count = 0;
        }
    }
    error = pthread_mutex_unlock(&semaphore->Mutex);
    assert_no_error(error);
}
