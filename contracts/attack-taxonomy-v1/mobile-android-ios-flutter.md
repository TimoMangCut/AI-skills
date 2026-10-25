# Mobile Super-Apps & Companion Apps (Android/Kotlin/Smali, iOS/Swift, Flutter, BLE) (`mobile-android-ios-flutter`)

> **Group:** I. Web, Mobile & API Core
> **Product Archetypes:** Mobile_Client_Android_iOS, Connected_Vehicle_Companion_App
> **Trigger Signals:** android, ios, kotlin, swift, flutter, dart, react-native, retrofit, okhttp, smali, apk, deeplink, bluetooth, ble, firebase

## [ BLOCK: mobile-exported-components-and-deeplinks ]
### Exported Activities/Services/Receivers, DeepLinks & WebView Bridges
- Audit `AndroidManifest.xml` (`android:exported="true"`, intent filters, custom URL schemes) and iOS `Info.plist` Universal Links.
- Trace untrusted DeepLink parameters flowing into `WebView.loadUrl()`, `addJavascriptInterface`, or internal authenticated API calls.
- Verify whether tokens or session cookies are automatically attached when a WebView loads an attacker-controlled URL.

## [ BLOCK: dynamic-host-routing-and-client-signing ]
### Retrofit/OkHttp Interceptors, Firebase Remote Config & Static Signing
- Enumerate ALL Retrofit/OkHttp service modules (do not stop at the primary client; check secondary modules like Auth0, Guest, EV, OwnerManual).
- Inspect `DynamicHostInterceptor` / Firebase Remote Config routing that switches endpoints per region or environment.
- Refute client-side HMAC/request-signing theater (`X-HASH`, static secrets in native `.so` or Dart/Kotlin constants) — treat client-known secrets as public.

## [ BLOCK: ble-phone-as-a-key-and-device-ota ]
### BLE Phone-as-a-Key (PAAK) & Mobile-Relayed Firmware Updates
- When the mobile app acts as a BLE key (e.g., eScooter/Vehicle PAAK) or relays firmware (`Cloud -> Phone -> BLE -> Vehicle`), trace pairing, nonce/anti-replay, and key revocation on lending/transfer.
- Verify whether the mobile app can flash downgraded or modified firmware packages onto the vehicle/device over BLE.
