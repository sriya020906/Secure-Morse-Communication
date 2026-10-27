/*
 * Sender firmware  (queue version)
 * STM32F401CCU6, CMSIS register-level, HSI = 16 MHz
 *
 * Topology:
 *   Sender USART1 PA9/PA10 <-> HC-05 <-> Laptop Bluetooth COM port
 *   Laptop Python bridge   <-> Receiver CP2102 <-> Receiver USART1
 *
 * Protocol:
 *   Laptop -> sender:   TEXT:<message>
 *   Sender -> laptop:   MSG:<T_ms>:<Morse>
 *   Laptop -> sender:   READY            (forwarded from receiver)
 *   Receiver responses: CIPHERTEXT:, ACK:, AUTH:, ERR:
 *
 * Message handling:
 *   - Incoming TEXT is cleaned (upper-case, A-Z 0-9 and single spaces only),
 *     validated, then pushed into a 4-slot ring-buffer queue (FIFO).
 *     A new message NEVER overwrites a queued one. If the queue is full the
 *     new message is rejected with ERR:QUEUE_FULL.
 *   - The head of the queue is sent only when the receiver has reported
 *     READY. If the receiver is off, messages wait in RAM.
 *   - With WAIT_FOR_AUTH = 1 the next message is released only after the
 *     previous one has been unlocked (AUTH:OK), because the receiver holds
 *     just one ciphertext. A timeout frees the queue if nobody enters a PIN.
 *
 * UART: 9600 baud, 8-N-1
 * KEY "STM" is for classroom demonstration only.
 * This is not production-grade encryption or authentication.
 */

#include "stm32f4xx.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* -------------------- Configuration -------------------- */

#define UART_BUF         600
#define LCD_ADDR         0x27u
#define KEY              "STM"

#define QN               4            /* queue slots                        */
#define MSG_MAX          150          /* max characters after cleaning      */
#define MSG_SLOT         (MSG_MAX + 1)
#define MORSE_MAX        560          /* frame stays below receiver BUF=600 */

#define WAIT_FOR_AUTH    1            /* 1 = next msg after AUTH:OK         */
#define AUTH_TIMEOUT_MS  120000UL     /* free the queue after 2 minutes     */
#define DEBOUNCE_MS      200UL

/* -------------------- Globals -------------------- */

/* USART2 is retained for optional debugging. */
static volatile char pc_rx[UART_BUF];
static volatile char bt_rx[UART_BUF];

static volatile uint16_t pc_n = 0;
static volatile uint16_t bt_n = 0;

static volatile uint8_t pc_line = 0;
static volatile uint8_t bt_line = 0;

static volatile uint8_t confirm_pressed = 0;
static volatile uint8_t send_pressed = 0;

static volatile uint8_t  receiver_ready = 0;
static volatile uint32_t ms_ticks = 0;
static volatile uint32_t last_confirm_ms = 0;
static volatile uint32_t last_send_ms = 0;

/* Used only from the main loop. */
static uint8_t  awaiting_auth = 0;
static uint32_t awaiting_since = 0;

/* Message queue (ring buffer): plaintext waiting to be sent. */
static char    msg_q[QN][MSG_SLOT];
static uint8_t q_head = 0;
static uint8_t q_tail = 0;
static uint8_t q_count = 0;

/* Large scratch buffers are static so they do not use the stack. */
static char cipher_buf[160];
static char morse_buf[MORSE_MAX + 1];
static char frame_buf[MORSE_MAX + 16];
static char bt_tmp[UART_BUF];
static char pc_tmp[UART_BUF];

static const char *morse[36] = {
    ".-", "-...", "-.-.", "-..", ".", "..-.", "--.", "....",
    "..", ".---", "-.-", ".-..", "--", "-.", "---", ".--.",
    "--.-", ".-.", "...", "-", "..-", "...-", ".--", "-..-",
    "-.--", "--..",
    "-----", ".----", "..---", "...--", "....-", ".....",
    "-....", "--...", "---..", "----."
};

/* -------------------- Delay and UART -------------------- */

static void delay(volatile uint32_t n)
{
    while (n--) {
        __NOP();
    }
}

static void uart_init(USART_TypeDef *u, int is_usart1)
{
    if (is_usart1) {
        RCC->APB2ENR |= RCC_APB2ENR_USART1EN;

        /* PA9 = USART1_TX, PA10 = USART1_RX */
        GPIOA->MODER &= ~((3u << 18) | (3u << 20));
        GPIOA->MODER |=  ((2u << 18) | (2u << 20));

        GPIOA->AFR[1] &= ~((15u << 4) | (15u << 8));
        GPIOA->AFR[1] |=  ((7u << 4) | (7u << 8));
    } else {
        RCC->APB1ENR |= RCC_APB1ENR_USART2EN;

        /* PA2 = USART2_TX, PA3 = USART2_RX */
        GPIOA->MODER &= ~((3u << 4) | (3u << 6));
        GPIOA->MODER |=  ((2u << 4) | (2u << 6));

        GPIOA->AFR[0] &= ~((15u << 8) | (15u << 12));
        GPIOA->AFR[0] |=  ((7u << 8) | (7u << 12));
    }

    u->CR1 = 0;
    u->BRR = 1667u; /* 9600 baud at 16 MHz */
    u->CR1 = USART_CR1_TE |
             USART_CR1_RE |
             USART_CR1_RXNEIE |
             USART_CR1_UE;
}

static void uart_putc(USART_TypeDef *u, char c)
{
    while (!(u->SR & USART_SR_TXE)) {
    }

    u->DR = (uint8_t)c;
}

static void uart_write(USART_TypeDef *u, const char *s)
{
    while (*s) {
        uart_putc(u, *s++);
    }
}

static void uart_line(USART_TypeDef *u, const char *s)
{
    uart_write(u, s);
    uart_putc(u, '\n');
}

/* Send GUI-visible status over Bluetooth. */
static void bt_status(const char *s)
{
    uart_line(USART1, s);
}

/* -------------------- GPIO and ADC -------------------- */

static void gpio_init(void)
{
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN |
                    RCC_AHB1ENR_GPIOBEN |
                    RCC_AHB1ENR_GPIOCEN;

    /* PA1 analog input for potentiometer */
    GPIOA->MODER &= ~(3u << 2);
    GPIOA->MODER |=  (3u << 2);

    /* PB13 LED output */
    GPIOB->MODER &= ~(3u << 26);
    GPIOB->MODER |=  (1u << 26);

    /* PA8 buzzer output */
    GPIOA->MODER &= ~(3u << 16);
    GPIOA->MODER |=  (1u << 16);

    /* PB1 and PB12 inputs with pull-ups */
    GPIOB->MODER &= ~((3u << 2) | (3u << 24));
    GPIOB->PUPDR &= ~((3u << 2) | (3u << 24));
    GPIOB->PUPDR |=  ((1u << 2) | (1u << 24));

    /* Enable SYSCFG for EXTI port mapping */
    RCC->APB2ENR |= RCC_APB2ENR_SYSCFGEN;

    /* EXTI1 mapped to PB1 */
    SYSCFG->EXTICR[0] &= ~(15u << 4);
    SYSCFG->EXTICR[0] |=  (1u << 4);

    /* EXTI12 mapped to PB12 */
    SYSCFG->EXTICR[3] &= ~(15u << 0);
    SYSCFG->EXTICR[3] |=  (1u << 0);

    EXTI->IMR |= (1u << 1) | (1u << 12);
    EXTI->FTSR |= (1u << 1) | (1u << 12);
    EXTI->RTSR &= ~((1u << 1) | (1u << 12));

    NVIC_EnableIRQ(EXTI1_IRQn);
    NVIC_EnableIRQ(EXTI15_10_IRQn);
}

static void adc_init(void)
{
    RCC->APB2ENR |= RCC_APB2ENR_ADC1EN;

    ADC1->CR1 = 0;
    ADC1->SMPR2 |= (7u << 3); /* Longer sample time, channel 1 */
    ADC1->SQR3 = 1u;
    ADC1->SQR1 = 0;
    ADC1->CR2 = ADC_CR2_ADON;
}

static uint16_t adc_read(void)
{
    ADC1->SR = 0;
    ADC1->CR2 |= ADC_CR2_SWSTART;

    while (!(ADC1->SR & ADC_SR_EOC)) {
    }

    return (uint16_t)ADC1->DR;
}

/* -------------------- I2C LCD -------------------- */

static void i2c_init(void)
{
    RCC->AHB1ENR |= RCC_AHB1ENR_GPIOBEN;
    RCC->APB1ENR |= RCC_APB1ENR_I2C1EN;

    /* PB6 = SCL, PB7 = SDA */
    GPIOB->MODER &= ~((3u << 12) | (3u << 14));
    GPIOB->MODER |=  ((2u << 12) | (2u << 14));

    GPIOB->OTYPER |= (1u << 6) | (1u << 7);
    GPIOB->OSPEEDR |= (3u << 12) | (3u << 14);

    GPIOB->PUPDR &= ~((3u << 12) | (3u << 14));

    GPIOB->AFR[0] &= ~((15u << 24) | (15u << 28));
    GPIOB->AFR[0] |=  ((4u << 24) | (4u << 28));

    I2C1->CR1 = 0;
    I2C1->CR2 = 16u;
    I2C1->CCR = 80u;
    I2C1->TRISE = 17u;
    I2C1->CR1 = I2C_CR1_PE;
}

static void i2c_start(void)
{
    I2C1->CR1 |= I2C_CR1_START;

    while (!(I2C1->SR1 & I2C_SR1_SB)) {
    }

    (void)I2C1->SR1;
}

static void i2c_send_addr(uint8_t addr)
{
    I2C1->DR = (uint8_t)(addr << 1);

    while (!(I2C1->SR1 & I2C_SR1_ADDR)) {
    }

    (void)I2C1->SR1;
    (void)I2C1->SR2;
}

static void i2c_byte(uint8_t b)
{
    while (!(I2C1->SR1 & I2C_SR1_TXE)) {
    }

    I2C1->DR = b;

    while (!(I2C1->SR1 & I2C_SR1_BTF)) {
    }
}

static void i2c_stop(void)
{
    I2C1->CR1 |= I2C_CR1_STOP;
}

static void lcd_exp(uint8_t x)
{
    i2c_start();
    i2c_send_addr(LCD_ADDR);
    i2c_byte(x | 0x08);
    i2c_stop();
}

static void lcd_nibble(uint8_t n, uint8_t rs)
{
    uint8_t x = (n & 0xF0) | 0x08 | (rs ? 1u : 0u);

    lcd_exp(x | 0x04);
    delay(3000);

    lcd_exp(x & (uint8_t)~0x04);
    delay(3000);
}

static void lcd_send(uint8_t v, uint8_t rs)
{
    lcd_nibble(v & 0xF0, rs);
    lcd_nibble((uint8_t)(v << 4), rs);
}

static void lcd_cmd(uint8_t v)
{
    lcd_send(v, 0);
}

static void lcd_data(uint8_t v)
{
    lcd_send(v, 1);
}

static void lcd_init(void)
{
    delay(900000);

    lcd_nibble(0x30, 0);
    delay(90000);

    lcd_nibble(0x30, 0);
    lcd_nibble(0x30, 0);
    lcd_nibble(0x20, 0);

    lcd_cmd(0x28);
    lcd_cmd(0x0C);
    lcd_cmd(0x06);
    lcd_cmd(0x01);

    delay(90000);
}

static void lcd_line(uint8_t row, const char *s)
{
    lcd_cmd(row ? 0xC0 : 0x80);

    size_t len = strlen(s);

    for (size_t i = 0; i < 16; i++) {
        char c = (i < len) ? s[i] : ' ';

        /* The HD44780 shows kana/symbols for bytes outside printable ASCII. */
        if ((unsigned char)c < 0x20u || (unsigned char)c > 0x7Du) {
            c = '?';
        }

        lcd_data((uint8_t)c);
    }
}

static void set_status(const char *a, const char *b)
{
    lcd_line(0, a);
    lcd_line(1, b);
}

/* -------------------- Encoding -------------------- */

static int letter_index(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }

    if (c >= '0' && c <= '9') {
        return 26 + c - '0';
    }

    return -1;
}

/*
 * Repeating-key shift cipher. The key position advances on every kept
 * character (letters, digits and spaces). The receiver's decrypt() must
 * count characters in exactly the same way.
 */
static void crypt_text(const char *in, char *out, int decrypt)
{
    size_t k = 0;

    for (size_t i = 0; in[i] && k < MSG_MAX; i++) {
        char c = in[i];

        if (c >= 'A' && c <= 'Z') {
            int shift = KEY[k % 3] - 'A';
            int x = c - 'A';

            x = decrypt
                ? (x - shift + 26) % 26
                : (x + shift) % 26;

            out[k++] = (char)('A' + x);
        } else if (c == ' ' || (c >= '0' && c <= '9')) {
            out[k++] = c;
        }
    }

    out[k] = '\0';
}

/*
 * Text -> Morse. Letters are separated by a space and words by "/".
 * Returns the Morse length, or 0 if the output would not fit (nothing
 * is ever silently truncated).
 */
static size_t morse_encode(const char *in, char *out, size_t cap)
{
    size_t n = 0;

    for (size_t i = 0; in[i]; i++) {
        if (in[i] == ' ') {
            if (n == 0) {
                continue;               /* no leading word separator */
            }

            while (n && out[n - 1] == ' ') {
                n--;
            }

            if (n + 3 > cap) {
                return 0;
            }

            out[n++] = '/';
            out[n++] = ' ';
            continue;
        }

        int idx = letter_index(in[i]);

        if (idx >= 0) {
            const char *m = morse[idx];
            size_t len = strlen(m);

            if (n + len + 2 > cap) {
                return 0;
            }

            memcpy(&out[n], m, len);
            n += len;
            out[n++] = ' ';
        }
    }

    while (n && out[n - 1] == ' ') {
        n--;
    }

    out[n] = '\0';
    return n;
}

/* Plaintext -> ciphertext -> Morse. Returns Morse length, 0 on failure. */
static size_t encode_message(const char *plain, char *morse_out, size_t cap)
{
    crypt_text(plain, cipher_buf, 0);
    return morse_encode(cipher_buf, morse_out, cap);
}

/*
 * In-place cleaning: upper-case, keep only A-Z, 0-9 and space, collapse
 * repeated spaces, trim leading and trailing spaces. This keeps the sender's
 * and the receiver's key positions aligned.
 */
static void sanitise(char *s)
{
    char *w = s;
    int prev_space = 1;                 /* 1 also drops leading spaces */

    for (const char *r = s; *r; r++) {
        char c = *r;

        if (c >= 'a' && c <= 'z') {
            c = (char)(c - 'a' + 'A');
        }

        if (c == ' ') {
            if (prev_space) {
                continue;
            }
            prev_space = 1;
        } else if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            prev_space = 0;
        } else {
            continue;
        }

        *w++ = c;
    }

    if (w > s && w[-1] == ' ') {
        w--;
    }

    *w = '\0';
}

/* -------------------- Buzzer -------------------- */

static void beep_twice(void)
{
    for (int i = 0; i < 2; i++) {
        GPIOA->ODR |= (1u << 8);
        delay(700000);

        GPIOA->ODR &= ~(1u << 8);
        delay(300000);
    }
}

/* -------------------- Message queue (ring buffer) -------------------- */

static int q_push(const char *s)
{
    if (q_count >= QN) {
        return 0;                       /* full */
    }

    strncpy(msg_q[q_tail], s, MSG_SLOT - 1);
    msg_q[q_tail][MSG_SLOT - 1] = '\0';

    q_tail = (uint8_t)((q_tail + 1u) % QN);
    q_count++;
    return 1;
}

static void q_pop(void)
{
    if (q_count) {
        q_head = (uint8_t)((q_head + 1u) % QN);
        q_count--;
    }
}

/* -------------------- Message handling -------------------- */

/*
 * TEXT:<message> from the laptop. The text is cleaned, validated and queued.
 * 'line' is a writable copy, so it is cleaned in place.
 */
static void process_text_command(char *line)
{
    if (strncmp(line, "TEXT:", 5) != 0) {
        return;
    }

    char *text = line + 5;

    sanitise(text);

    if (!text[0]) {
        set_status("EMPTY MESSAGE", "Enter text again");
        bt_status("ERR:EMPTY_MESSAGE");
        return;
    }

    if (strlen(text) > MSG_MAX ||
        encode_message(text, morse_buf, sizeof(morse_buf)) == 0) {
        set_status("MESSAGE TOO LONG", "Shorten it");
        bt_status("ERR:TOO_LONG");
        return;
    }

    if (!q_push(text)) {
        set_status("QUEUE FULL", "Wait and retry");
        bt_status("ERR:QUEUE_FULL");
        return;
    }

    set_status("TEXT RECEIVED", text);
    bt_status("STATUS:TEXT_RECEIVED");
}

/* Send the message at the head of the queue as one MSG frame. */
static void send_head(void)
{
    const char *msg = msg_q[q_head];
    char l1[17];
    char l2[17];
    char status[64];

    if (encode_message(msg, morse_buf, sizeof(morse_buf)) == 0) {
        bt_status("ERR:ENCODING_FAILED");
        set_status("ENCODING ERROR", "Message dropped");
        q_pop();
        return;
    }

    uint16_t a = adc_read();

    const char *speed;
    int t;

    if (a < 1365) {
        speed = "SLOW";
        t = 300;
    } else if (a < 2730) {
        speed = "MEDIUM";
        t = 150;
    } else {
        speed = "FAST";
        t = 75;
    }

    snprintf(frame_buf, sizeof(frame_buf), "MSG:%d:%s", t, morse_buf);
    uart_line(USART1, frame_buf);

    snprintf(l1, sizeof(l1), "SPEED: %s", speed);
    snprintf(l2, sizeof(l2), "Sent %u chars", (unsigned)strlen(msg));
    set_status(l1, l2);

    snprintf(status, sizeof(status), "STATUS:SENT:%s", speed);
    bt_status(status);

    q_pop();

    /* Stop-and-wait: the next READY re-enables sending. */
    receiver_ready = 0;
    awaiting_auth = WAIT_FOR_AUTH ? 1u : 0u;
    awaiting_since = ms_ticks;
}

/*
 * Send queued messages while the receiver is available. Called whenever
 * something changes: new text, READY received, or the send button pressed.
 */
static void try_send(void)
{
    while (q_count && receiver_ready &&
           !(WAIT_FOR_AUTH && awaiting_auth)) {
        send_head();
    }
}

/*
 * Incoming USART1 lines are from the laptop bridge.
 *
 * TEXT:       new GUI message
 * READY:      receiver is ready, forwarded by the bridge
 * CIPHERTEXT: receiver's response
 * AUTH:       receiver's PIN verification result
 * ERR:        receiver or bridge error
 */
static void handle_bt_line(char *line)
{
    if (!strncmp(line, "TEXT:", 5)) {
        process_text_command(line);
        try_send();
        return;
    }

    if (!strcmp(line, "READY")) {
        receiver_ready = 1;
        bt_status("STATUS:RECEIVER_READY");
        try_send();
        return;
    }

    if (!strncmp(line, "CIPHERTEXT:", 11)) {
        uart_line(USART2, line);
        set_status("CIPHER RECEIVED", "Awaiting PIN");
        return;
    }

    if (!strncmp(line, "AUTH:DENIED", 11)) {
        uart_line(USART2, line);
        GPIOB->ODR ^= (1u << 13);
        beep_twice();
        set_status("PIN DENIED", "Try again");
        return;
    }

    if (!strncmp(line, "AUTH:OK:", 8)) {
        uart_line(USART2, line);
        GPIOB->ODR |= (1u << 13);
        set_status("AUTH SUCCESS", "Message unlocked");

        /* The receiver's READY follows this line and releases the next one. */
        awaiting_auth = 0;
        return;
    }

    if (!strncmp(line, "ERR:", 4)) {
        uart_line(USART2, line);
        set_status("RECEIVER ERROR", line + 4);

        /* The receiver did not keep a message, so do not wait for a PIN. */
        awaiting_auth = 0;
        return;
    }

    if (!strncmp(line, "ACK:", 4)) {
        uart_line(USART2, line);
        return;
    }

    /* Ignore other lines rather than treating them as PC commands. */
    uart_line(USART2, line);
}

/*
 * Optional legacy USART2 command handler.
 */
static void process_pc_line(char *line)
{
    if (!strncmp(line, "TEXT:", 5)) {
        process_text_command(line);
        try_send();
    } else if (!strncmp(line, "PIN:", 4)) {
        uart_line(USART1, line);
    }
}

/* -------------------- Interrupt handlers -------------------- */

void SysTick_Handler(void)
{
    ms_ticks++;
}

void USART1_IRQHandler(void)
{
    if (USART1->SR & USART_SR_RXNE) {
        char c = (char)USART1->DR;

        if (c == '\n' || c == '\r') {
            if (bt_n && !bt_line) {
                bt_rx[bt_n] = '\0';
                bt_line = 1;
                bt_n = 0;
            } else if (bt_line) {
                /* A complete line is waiting for main(). */
                bt_n = 0;
            }
        } else if (!bt_line) {
            if (bt_n < UART_BUF - 1) {
                bt_rx[bt_n++] = c;
            } else {
                bt_n = 0;
            }
        }
    }
}

void USART2_IRQHandler(void)
{
    if (USART2->SR & USART_SR_RXNE) {
        char c = (char)USART2->DR;

        if (c == '\n' || c == '\r') {
            if (pc_n && !pc_line) {
                pc_rx[pc_n] = '\0';
                pc_line = 1;
                pc_n = 0;
            } else if (pc_line) {
                pc_n = 0;
            }
        } else if (!pc_line) {
            if (pc_n < UART_BUF - 1) {
                pc_rx[pc_n++] = c;
            } else {
                pc_n = 0;
            }
        }
    }
}

void EXTI1_IRQHandler(void)
{
    if (EXTI->PR & (1u << 1)) {
        EXTI->PR = (1u << 1);

        if ((uint32_t)(ms_ticks - last_confirm_ms) >= DEBOUNCE_MS) {
            last_confirm_ms = ms_ticks;
            confirm_pressed = 1;
        }
    }
}

void EXTI15_10_IRQHandler(void)
{
    if (EXTI->PR & (1u << 12)) {
        EXTI->PR = (1u << 12);

        if ((uint32_t)(ms_ticks - last_send_ms) >= DEBOUNCE_MS) {
            last_send_ms = ms_ticks;
            send_pressed = 1;
        }
    }
}

/* -------------------- Main -------------------- */

int main(void)
{
    SystemCoreClockUpdate();
    SysTick_Config(SystemCoreClock / 1000U);   /* 1 ms tick */

    gpio_init();
    adc_init();
    i2c_init();
    lcd_init();

    uart_init(USART1, 1); /* HC-05 */
    uart_init(USART2, 0); /* Optional debug UART */

    NVIC_SetPriority(USART1_IRQn, 1);
    NVIC_EnableIRQ(USART1_IRQn);

    NVIC_SetPriority(USART2_IRQn, 1);
    NVIC_EnableIRQ(USART2_IRQn);

    set_status("SENDER READY", "Waiting Bluetooth");

    bt_status("STATUS:SENDER_READY");
    uart_line(USART2, "STATUS:SENDER_READY");

    while (1) {
        if (bt_line) {
            __disable_irq();
            strncpy(bt_tmp, (const char *)bt_rx, sizeof(bt_tmp) - 1);
            bt_tmp[sizeof(bt_tmp) - 1] = '\0';
            bt_line = 0;
            __enable_irq();

            handle_bt_line(bt_tmp);
        }

        if (pc_line) {
            __disable_irq();
            strncpy(pc_tmp, (const char *)pc_rx, sizeof(pc_tmp) - 1);
            pc_tmp[sizeof(pc_tmp) - 1] = '\0';
            pc_line = 0;
            __enable_irq();

            process_pc_line(pc_tmp);
        }

        if (confirm_pressed) {
            confirm_pressed = 0;

            uint16_t a = adc_read();

            const char *s =
                a < 1365 ? "SLOW" :
                a < 2730 ? "MEDIUM" : "FAST";

            char b[17];
            snprintf(b, sizeof(b), "SPEED: %s", s);
            set_status("ADC SPEED MODE", b);
        }

        if (send_pressed) {
            send_pressed = 0;

            if (!q_count) {
                set_status("NO MESSAGE", "Use desktop UI");
            } else if (!receiver_ready) {
                set_status("WAITING READY", "Receiver busy");
            } else if (WAIT_FOR_AUTH && awaiting_auth) {
                set_status("WAITING PIN", "Authenticate 1st");
            } else {
                try_send();
            }
        }

        /* Free the queue if nobody authenticates the previous message. */
        if (awaiting_auth &&
            (uint32_t)(ms_ticks - awaiting_since) >= AUTH_TIMEOUT_MS) {
            awaiting_auth = 0;
            set_status("AUTH TIMEOUT", "Next msg freed");
            bt_status("STATUS:AUTH_TIMEOUT");
            try_send();
        }
    }
}