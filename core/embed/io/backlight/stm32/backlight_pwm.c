/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <trezor_bsp.h>
#include <trezor_rtl.h>

#include <io/backlight.h>

#include <math.h>

// The backlight is built from several LED strings sharing a common anode. Each
// string returns through its own MCU pin acting as a low-side switch, so the
// strings have to be driven with the *same* timer in lockstep (one channel per
// string, identical duty cycle). Because the pins sink the cathodes, the
// channels are driven active-low: the LED conducts while the output is low.

// PWM frequency [Hz] - high enough to be flicker- and audible-noise-free.
#define BACKLIGHT_PWM_FREQ 10000
// PWM counter resolution (timer period in ticks).
#define BACKLIGHT_PWM_TIM_PERIOD 1000

// Input level below this is treated as fully off.
#define INPUT_OFFSET 1

// Timer channels driving the individual backlight legs.
static const uint32_t g_pwm_channels[] = BACKLIGHT_PWM_CHANNELS;
#define BACKLIGHT_PWM_CH_COUNT \
  (sizeof(g_pwm_channels) / sizeof(g_pwm_channels[0]))

// Backlight driver state
typedef struct {
  // Set if driver is initialized
  bool initialized;
  // Current backlight level in range 0-255
  uint8_t current_level;
  // Maximal allowed backlight level
  uint8_t max_level;
  // Gamma correction exponent
  float gamma_exp;
  // PWM timer handle
  TIM_HandleTypeDef tim;
} backlight_driver_t;

// Backlight driver instance
static backlight_driver_t g_backlight_driver = {
    .initialized = false,
};

// Applies gamma correction to a brightness input value and scales it to the
// PWM compare range.
//
//   OUT = ( ( (max(IN, in_offset) - in_offset) / (in_max - in_offset) ) ^
//         gamma_exp) * out_max
static inline uint32_t gamma_correction(uint8_t in, uint8_t in_offset,
                                        uint8_t in_max, float gamma_exp,
                                        uint32_t out_max) {
  float out;

  out = (float)(MAX(in, in_offset) - in_offset) /
        (in_max - in_offset);  // Input normalization to <0;1>
  out = powf(out, gamma_exp);  // Gamma correction
  out = out * out_max;         // Output denormalization to <0;out_max>

  return (uint32_t)out;
}

bool backlight_init(backlight_action_t action, float gamma_exp) {
  backlight_driver_t *drv = &g_backlight_driver;

  if (drv->initialized) {
    return true;
  }

  uint8_t initial_level = 0;

  if (action == BACKLIGHT_RETAIN) {
    // Estimate the current level from the already running timer
    // (configured by a previous boot stage) to avoid a visible glitch.
    // All channels carry the same duty cycle, so read back the compare
    // register of the first configured channel (not necessarily CCR1).
    TIM_HandleTypeDef tim = {.Instance = BACKLIGHT_PWM_TIM};
    uint32_t arr = BACKLIGHT_PWM_TIM->ARR;
    uint32_t ccr = __HAL_TIM_GET_COMPARE(&tim, g_pwm_channels[0]);
    uint32_t level = (ccr * BACKLIGHT_MAX_LEVEL) / (arr + 1);
    initial_level = MIN(level, BACKLIGHT_MAX_LEVEL);
  }

  memset(drv, 0, sizeof(backlight_driver_t));
  drv->gamma_exp = gamma_exp;
  drv->max_level = BACKLIGHT_MAX_LEVEL;

  // Enable peripheral clocks
  BACKLIGHT_PWM_PORT_CLK_EN();

  // Initialize the PWM timer
  BACKLIGHT_PWM_TIM_FORCE_RESET();
  BACKLIGHT_PWM_TIM_RELEASE_RESET();
  BACKLIGHT_PWM_TIM_CLK_EN();

  drv->tim.State = HAL_TIM_STATE_RESET;
  drv->tim.Instance = BACKLIGHT_PWM_TIM;
  drv->tim.Init.Period = BACKLIGHT_PWM_TIM_PERIOD - 1;
  drv->tim.Init.Prescaler =
      SystemCoreClock / (BACKLIGHT_PWM_FREQ * BACKLIGHT_PWM_TIM_PERIOD) - 1;
  drv->tim.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
  drv->tim.Init.CounterMode = TIM_COUNTERMODE_UP;
  drv->tim.Init.RepetitionCounter = 0;
  drv->tim.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_ENABLE;
  if (HAL_TIM_PWM_Init(&drv->tim) != HAL_OK) {
    return false;
  }

  // Configure all channels: PWM mode 1, active-low (cathode sink), off.
  TIM_OC_InitTypeDef oc_init = {0};
  oc_init.OCMode = TIM_OCMODE_PWM1;
  oc_init.Pulse = 0;
  oc_init.OCPolarity = TIM_OCPOLARITY_LOW;
  oc_init.OCFastMode = TIM_OCFAST_DISABLE;
  for (size_t i = 0; i < BACKLIGHT_PWM_CH_COUNT; i++) {
    if (HAL_TIM_PWM_ConfigChannel(&drv->tim, &oc_init, g_pwm_channels[i]) !=
        HAL_OK) {
      return false;
    }
  }

  // Route the GPIO pins to the timer
  GPIO_InitTypeDef GPIO_PwmInit = {0};
  GPIO_PwmInit.Mode = GPIO_MODE_AF_PP;
  GPIO_PwmInit.Pull = GPIO_NOPULL;
  GPIO_PwmInit.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_PwmInit.Alternate = BACKLIGHT_PWM_TIM_AF;
  GPIO_PwmInit.Pin = BACKLIGHT_PWM_PINS;
  HAL_GPIO_Init(BACKLIGHT_PWM_PORT, &GPIO_PwmInit);

  // Start PWM generation on all channels
  for (size_t i = 0; i < BACKLIGHT_PWM_CH_COUNT; i++) {
    if (HAL_TIM_PWM_Start(&drv->tim, g_pwm_channels[i]) != HAL_OK) {
      return false;
    }
  }

  drv->initialized = true;

  backlight_set(initial_level);

  return true;
}

void backlight_deinit(backlight_action_t action) {
  backlight_driver_t *drv = &g_backlight_driver;

  if (!drv->initialized) {
    return;
  }

  if (action == BACKLIGHT_RESET) {
    // Stop PWM and park the GPIO pins so the LEDs stay off
    for (size_t i = 0; i < BACKLIGHT_PWM_CH_COUNT; i++) {
      HAL_TIM_PWM_Stop(&drv->tim, g_pwm_channels[i]);
    }

    GPIO_InitTypeDef GPIO_PwmInit = {0};
    GPIO_PwmInit.Mode = GPIO_MODE_ANALOG;
    GPIO_PwmInit.Pull = GPIO_NOPULL;
    GPIO_PwmInit.Speed = GPIO_SPEED_FREQ_LOW;
    GPIO_PwmInit.Pin = BACKLIGHT_PWM_PINS;
    HAL_GPIO_Init(BACKLIGHT_PWM_PORT, &GPIO_PwmInit);

    BACKLIGHT_PWM_TIM_FORCE_RESET();
    BACKLIGHT_PWM_TIM_RELEASE_RESET();
    BACKLIGHT_PWM_TIM_CLK_DIS();
  }
  // For BACKLIGHT_RETAIN the timer is left running so the backlight stays lit
  // across the deinitialization.

  drv->initialized = false;
}

bool backlight_set(uint8_t val) {
  backlight_driver_t *drv = &g_backlight_driver;

  if (!drv->initialized) {
    return false;
  }

  uint8_t level = MIN(val, drv->max_level);

  uint32_t pulse = 0;
  if (level >= INPUT_OFFSET) {
    pulse = gamma_correction(level, INPUT_OFFSET, BACKLIGHT_MAX_LEVEL,
                             drv->gamma_exp, BACKLIGHT_PWM_TIM_PERIOD);
  }

  for (size_t i = 0; i < BACKLIGHT_PWM_CH_COUNT; i++) {
    __HAL_TIM_SET_COMPARE(&drv->tim, g_pwm_channels[i], pulse);
  }

  drv->current_level = val;

  return true;
}

uint8_t backlight_get(void) {
  backlight_driver_t *drv = &g_backlight_driver;

  if (!drv->initialized) {
    return 0;
  }

  return drv->current_level;
}

bool backlight_set_max_level(uint8_t max_level) {
  backlight_driver_t *drv = &g_backlight_driver;

  if (!drv->initialized) {
    return false;
  }

  drv->max_level = max_level;

  // Reapply the current level with the new limit
  return backlight_set(drv->current_level);
}
