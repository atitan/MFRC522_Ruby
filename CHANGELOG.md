## MFRC522 3.0.0  ##

*   Replace PiPiper with Fubuki for more stable SPI communication
*   FIXED: ISO 14443-4 transceive error

## MFRC522 2.0.0  ##

*   API CHANGED: Module `Mifare` renamed to `MIFARE`
*   API CHANGED: Method `resume_communication` renamed to `restart_communication`
*   API CHANGED: Class `ISO144434` merged into class `PICC`
*   API CHANGED: Method `select` and `deselect` in Class `ISO144434` are renamed to `iso_select` and `iso_deselect` respectively
*   API CHANGED: Method `transceive` in class `PICC` renamed to `picc_transceive`
*   API CHANGED: Method `transceive` in class `ISO144434` renamed to `iso_transceive`
*   API CHANGED: Method `identify_model` in class `MFRC522` moved to class `PICC`
*   NEW API: Exception `UsageError` introduced for user-input error at method level
*   NEW API: Class `MIFARE::Key` added method `padding_mode` to control padding method on every encrypt/decrypt operation
*   NEW API: Class `MIFARE::DESFire` added some methods to reflect new commands supported by DESfire EV1
*   NEW API: Class `MIFARE::UltraLightEV1` introduced
*   NEW API: Class `MIFARE::Plus` introduced
*   NEW FEATURE: Method `picc_select` in `MFRC522` now accept parameter to disable anti-collision
*   FIXED: Broken Structs in class `MIFARE::DESFire`
*   FIXED: Transceive using baud rate over 106kbd

## MFRC522 1.0.6  ##

*   Fix broken dirty buffer detection in `picc_select`.
*   Improve anti-collision algorithm.
*   Lower default SPI clock to 1Mhz for better compatibility.

## MFRC522 1.0.5  ##

*   Ensure buffer is valid before doing any transmission during `picc_select`.

## MFRC522 1.0.3 & 1.0.4  ##

*   Enhance collision handling mechanism.

## MFRC522 1.0.2 ##

*   Improve error handling in `picc_select`

## MFRC522 1.0.1 ##

*   Rename `KEY_ENCRYPTION` to `KEY_COMMUNICATION` in `DESFire`

## MFRC522 1.0.0 ##

*   Use exception on error handling at higher level of abstraction.

*   Add support for Mifare DESFire EV1.

*   Add suuport for ISO 14443-4 protocol.

## MFRC522 0.2.0 ##

*   Introduce PICC abstraction.

*   Add support for Mifare Ultralight and Mifare Ultralight C.

*   Class name now comes all uppercased.

## Mfrc522 0.1.2 ##

*   Add addtional check on buffer while selecting card.

## Mfrc522 0.1.0 ##

*   Fixed critical bug in `picc_select`.

*   `mifare_authenticate` and `mifare_deauthenticate` renamed to
    `mifare_crypto1_authenticate` and `mifare_crypto1_deauthenticate` respectively.

## Mfrc522 0.0.1 ##

*   Initial release.
