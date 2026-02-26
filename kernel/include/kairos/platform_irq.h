/**
 * kernel/include/kairos/platform_irq.h - Platform bus IRQ helpers
 */

#ifndef _KAIROS_PLATFORM_IRQ_H
#define _KAIROS_PLATFORM_IRQ_H

#include <kairos/device.h>
#include <kairos/types.h>

int platform_device_get_irq(const struct device *dev, size_t index);
int platform_device_request_irq(struct device *dev, size_t index,
                                void (*handler)(void *), void *arg,
                                uint32_t flags);
int platform_device_free_irq(struct device *dev, size_t index,
                             void (*handler)(void *), void *arg);
int platform_device_free_irq_sync(struct device *dev, size_t index,
                                  void (*handler)(void *), void *arg);

#endif
