# Secure Morse Code Communication Using STM32 and Bluetooth

## Overview

This project implements an embedded text communication system using the STM32F401CCU6 microcontroller. It combines encryption, Morse code encoding and decoding, serial communication, and PIN-based authentication to demonstrate a communication pipeline between a sender and a receiver.

The sender encrypts a text message, encodes the result into Morse code, and transmits it. At the receiving end, the Morse code is decoded, the user is authenticated, and the encrypted message is decrypted to recover the original text.

## Features

- Text message encryption and decryption
- Morse code encoding and decoding
- Sender-to-receiver communication
- PIN-based authentication
- UART/USART serial communication
- Embedded hardware interfacing
- Optional Python GUI for sending messages and monitoring communication, if implemented

## System Architecture

**Sender**
1. Accept a text message.
2. Encrypt the message.
3. Encode the encrypted data into Morse code.
4. Transmit the encoded message.

**Receiver**
1. Receive the transmitted data.
2. Decode the Morse code.
3. Authenticate the user using PIN verification.
4. Decrypt the message after successful authentication.
5. Display or output the recovered plaintext.

## Hardware Requirements

- STM32F401CCU6 development board
- HC-05 Bluetooth module, if used in the final setup
- CP2102 USB-to-TTL adapter for serial debugging/programming where applicable
- Push buttons and LEDs, as implemented
- 16×2 LCD with I2C interface, if integrated
- Jumper wires and suitable power supply

## Software and Tools

- Keil µVision
- Embedded C
- STM32 CMSIS/register-level programming
- Python, Tkinter and PySerial

## Hardware Connections

### UART1 — STM32F401CCU6

| STM32 pin | Connection |
|---|---|
| PA9 | USART1_TX |
| PA10 | USART1_RX |
| GND | Common ground with the serial adapter |

For serial debugging, connect TX to the other device's RX and RX to its TX. Verify voltage compatibility before connecting hardware.

### I2C LCD

| STM32 pin | Function |
|---|---|
| PB8 | I2C SCL |
| PB9 | I2C SDA |

The LCD address and connections should match the actual hardware configuration.

## Getting Started

1. Clone or download this repository.
2. Open the relevant firmware project in Keil µVision.
3. Check the microcontroller configuration, clock settings, pin assignments, and communication settings.
4. Build the firmware and resolve any compilation errors.
5. Flash the sender and receiver firmware onto their respective boards, if using two boards.
6. Connect the hardware according to the circuit diagram.
7. Test message transmission, Morse decoding, PIN authentication, and decryption.
8. If available, launch the Python GUI using the instructions in the `python-gui` directory.

## Testing

Test the following functions individually before testing the complete system:

- UART transmission and reception
- Morse code encoding and decoding
- Correct message recovery after decryption
- Successful authentication with the correct PIN
- Rejection of an incorrect PIN
- Handling of invalid or incomplete messages

Document the results from the actual hardware tests.

## Security Note

The encryption and PIN authentication mechanisms are intended for educational demonstration unless independently evaluated for security. This project should not be treated as production-grade secure communication without a suitable cryptographic design and testing.
