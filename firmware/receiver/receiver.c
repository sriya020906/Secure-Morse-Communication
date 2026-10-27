
/*
 * Receiver firmware
 * STM32F401CCU6, CMSIS register-level, HSI = 16 MHz
 *
 * Hardware:
 *   USART1 TX: PA9  -> CP2102 RX
 *   USART1 RX: PA10 <- CP2102 TX
 *   Receiver LED: PB13
 *
 * Sender-only hardware (not controlled here):
 *   Potentiometer: PA1
 *   Buzzer:        PA8
 *   Sender LED:    PB14
 *
 * Commands received:
 *   MSG:<duration_ms>:<Morse>
 *   PIN:<pin>
 *
 * Replies:
 *   CIPHERTEXT:<decoded_ciphertext>
 *   ACK:RECEIVED
 *   AUTH:OK:<plaintext>
 *   AUTH:DENIED
 *   ERR:<reason>
 *   READY
 *
 * UART: 9600 baud, 8-N-1
 *
 * Classroom demonstration only:
 * KEY "STM" and PIN "1234" are not secure protection.
 */

#include "stm32f4xx.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define BUF       600U
#define PIN_CODE  "1234"
#define KEY       "STM"

#define LED_PIN   13U

static volatile char rx[BUF];
static volatile uint16_t rx_n = 0;
static volatile uint8_t line_ready = 0;

/* Decoded ciphertext kept in RAM until PIN verification. */
static char g_cipher[170] = {0};

/* -------------------- Morse lookup -------------------- */

static const char *morse[36] = {
    ".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....",
    "..", ".---", "-.-", ".-..", "--", "-.", "---", ".--.",
    "--.-", ".-.", "...", "-", "..-", "...-", ".--", "-..-",
    "-.--", "--..",
    "-----", ".----", "..---", "...--", "....-", ".....",
    "-....", "--...", "---..", "----."
};

/* -------------------- GPIO -------------------- */

static void gpio_init(void)
{
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOBEN;

    /* PB13: receiver status LED output. */
    GPIOB->MODER &= ~(3U << (LED_PIN * 2U));
    GPIOB->MODER |=  (1U << (LED_PIN * 2U));

    /* Push-pull output, low speed. */
    GPIOB->OTYPER &= ~(1U << LED_PIN);
    GPIOB->OSPEEDR &= ~(3U << (LED_PIN * 2U));

    /* Start with LED off. */
    GPIOB->BSRR = (1U << (LED_PIN + 16U));
}

static void led_on(void)
{
    GPIOB->BSRR = (1U << LED_PIN);
}

static void led_off(void)
{
    GPIOB->BSRR = (1U << (LED_PIN + 16U));
}

/* -------------------- UART -------------------- */

static void uart_init(void)
{
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN;
    RCC->APB2ENR |= RCC_APB2ENR_USART1EN;

    /* PA9 = USART1_TX, PA10 = USART1_RX, AF7. */
    GPIOA->MODER &= ~((3U << 18) | (3U << 20));
    GPIOA->MODER |=  ((2U << 18) | (2U << 20));

    GPIOA->AFR[1] &= ~((15U << 4) | (15U << 8));
    GPIOA->AFR[1] |=  ((7U << 4) | (7U << 8));

    USART1->CR1 = 0;
    USART1->BRR = 1667U; /* 9600 baud at 16 MHz */

    USART1->CR1 = USART_CR1_TE |
                  USART_CR1_RE |
                  USART_CR1_RXNEIE |
                  USART_CR1_UE;
}

static void uart_putc(char c)
{
    while (!(USART1->SR & USART_SR_TXE)) {
    }

    USART1->DR = (uint8_t)c;
}

static void send(const char *s)
{
    while (*s) {
        uart_putc(*s++);
    }

    uart_putc('\n');
}

/* -------------------- Decryption -------------------- */

/*
 * Demonstration Caesar-style decryption.
 * The sender's encryption algorithm must match this function.
 */
static void decrypt(const char *in, char *out)
{
    size_t j = 0;

    for (size_t i = 0; in[i] && j < 150U; i++) {
        char c = in[i];

        if (c >= 'A' && c <= 'Z') {
            int shift = KEY[j % 3U] - 'A';

            out[j++] = (char)(
                'A' + (c - 'A' - shift + 26) % 26
            );
        } else if (c == ' ' || (c >= '0' && c <= '9')) {
            out[j++] = c;
        }
    }

    out[j] = '\0';
}

/* -------------------- Morse decoding -------------------- */

static void decode_morse(const char *s, char *out, size_t cap)
{
    char token[8];
    size_t token_len = 0;
    size_t out_len = 0;

    for (size_t i = 0; ; i++) {
        char c = s[i];

        if (c == '.' || c == '-') {
            if (token_len < sizeof(token) - 1U) {
                token[token_len++] = c;
            } else {
                /* Invalid or oversized Morse symbol. */
                token_len = 0;
            }
        } else if (c == ' ' || c == '/' || c == '\0') {

            if (token_len > 0U) {
                token[token_len] = '\0';

                int found = -1;

                for (int k = 0; k < 36; k++) {
                    if (strcmp(token, morse[k]) == 0) {
                        found = k;
                        break;
                    }
                }

                if (found >= 0 && out_len + 1U < cap) {
                    if (found < 26) {
                        out[out_len++] = (char)('A' + found);
                    } else {
                        out[out_len++] =
                            (char)('0' + found - 26);
                    }
                }

                token_len = 0;
            }

            /* Slash is used as a word separator. */
            if (c == '/' && out_len + 1U < cap &&
                out_len > 0U && out[out_len - 1U] != ' ') {
                out[out_len++] = ' ';
            }

            if (c == '\0') {
                break;
            }
        } else {
            /* Reject unexpected characters in a Morse frame. */
            token_len = 0;
        }
    }

    out[out_len] = '\0';
}

/* -------------------- Frame processing -------------------- */

static void process(char *s)
{
    if (strncmp(s, "MSG:", 4U) == 0) {
        char *separator = strchr(s + 4, ':');

        if (separator == NULL) {
            send("ERR:BAD_FRAME");
            return;
        }

        *separator = '\0';

        /*
         * Duration is part of the protocol. The receiver currently
         * decodes the Morse text but does not perform Morse playback.
         */
        char *endptr = NULL;
        long duration_ms = strtol(s + 4, &endptr, 10);

        if (endptr == s + 4 || *endptr != '\0' ||
            duration_ms < 1L || duration_ms > 10000L) {
            send("ERR:BAD_DURATION");
            return;
        }

        char cipher[170] = {0};

        decode_morse(separator + 1, cipher, sizeof(cipher));

        if (cipher[0] == '\0') {
            send("ERR:EMPTY_MESSAGE");
            return;
        }

        strncpy(g_cipher, cipher, sizeof(g_cipher) - 1U);
        g_cipher[sizeof(g_cipher) - 1U] = '\0';

        /* A message has been received. */
        led_on();

        char reply[200];

        snprintf(reply, sizeof(reply), "CIPHERTEXT:%s", g_cipher);
        send(reply);
        send("ACK:RECEIVED");

    } else if (strncmp(s, "PIN:", 4U) == 0) {

        if (g_cipher[0] == '\0') {
            send("ERR:NO_MESSAGE");
            return;
        }

        if (strcmp(s + 4, PIN_CODE) == 0) {
            char plaintext[170];
            char reply[220];

            decrypt(g_cipher, plaintext);

            snprintf(reply, sizeof(reply),
                     "AUTH:OK:%s", plaintext);
            send(reply);

            /* Successful authentication. */
            led_on();

        } else {
            send("AUTH:DENIED");

            /* Incorrect PIN. */
            led_off();
        }

    } else {
        send("ERR:UNKNOWN_COMMAND");
    }
}

/* -------------------- USART1 receive interrupt -------------------- */

void USART1_IRQHandler(void)
{
    if (USART1->SR & USART_SR_RXNE) {
        char c = (char)USART1->DR;

        if (c == '\n' || c == '\r') {
            if (rx_n > 0U && !line_ready) {
                rx[rx_n] = '\0';
                line_ready = 1U;
                rx_n = 0U;
            } else if (line_ready) {
                /* Wait until the main loop consumes the current line. */
                rx_n = 0U;
            }
        } else if (!line_ready) {
            if (rx_n < BUF - 1U) {
                rx[rx_n++] = c;
            } else {
                /* Oversized input: discard the partial line. */
                rx_n = 0U;
            }
        }
    }
}

/* -------------------- Main -------------------- */

int main(void)
{
    SystemCoreClockUpdate();

    gpio_init();
    uart_init();

    NVIC_SetPriority(USART1_IRQn, 1U);
    NVIC_EnableIRQ(USART1_IRQn);

    send("BOOT:RECEIVER");
    send("READY");

    while (1) {
        if (line_ready) {
            char command[BUF];

            __disable_irq();

            strncpy(command, (const char *)rx, sizeof(command) - 1U);
            command[sizeof(command) - 1U] = '\0';

            line_ready = 0U;

            __enable_irq();

            process(command);

            /* Notify the sender that this command was processed. */
            send("READY");
        }
    }
}
