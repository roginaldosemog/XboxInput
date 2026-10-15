/* Build-only fixture using the actual upstream parser. NOT a controller driver
 * and NOT approved for deployment. No kernel imports or hardware access.
 * No claim of compatibility between the compiler's ABI and the Xbox kernel ABI.
 */
#include "gip_gamepad_parser.h"

extern "C" int xsdk_start(void) {
    const uint8_t payload[14] = {0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    XboxInputGipGamepadState state;
    return XboxInputParseGipGamepadPayload(payload, sizeof payload, &state) &&
        state.buttons == 0x1000 ? 0 : 1;
}
