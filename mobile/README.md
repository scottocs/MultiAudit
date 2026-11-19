# MultiAudit iPhone client

The phone performs owner Setup and Store, uploads data and tags, and retains
its signed public registry. The cloud reconstructs the uploaded authentication
trees and runs ProofGen with public parameters. Local Verify is optional and
disabled by default in the interactive UI. A skipped check is never reported as
a successful verification.

Import files from Files, or use the synthetic benchmark collection. Real byte
files use 31-byte sectors and padding; the benchmark uses canonical 32-byte
field elements with `n=3907`, `s=80`, and `c=690`. Each benchmark file therefore
contains 10,001,920 encoded data bytes. Files are preprocessed and uploaded
sequentially to bound phone memory. Xu and Yu retain their native authentication
and verification equations, and all three use the existing shared arithmetic.

Build on a Mac with Xcode and Go:

```sh
zsh mobile/build.sh iphoneos
xcodebuild -project mobile/MultiAudit.xcodeproj -scheme MultiAudit \
  -configuration Release -sdk iphoneos -destination 'id=YOUR_DEVICE_UDID' \
  -derivedDataPath /private/tmp/multiaudit-ios-device \
  DEVELOPMENT_TEAM=YOUR_TEAM -allowProvisioningUpdates build
```

Install the Release app using Xcode or `xcrun devicectl device install app`.
Build and run `mobile/server` on the experiment host; the server writes its
temporary account token to the configured private output directory. The device
and server must have a working network route. Import the account token into
the app's connection settings; owner signing and setup secrets are generated
on the phone and are not sent to the server.

The local experiment listener uses HTTP on a private network with synthetic
data. A deployed personal-storage service needs HTTPS and persistent account
and key management. This prototype keeps its owner session in memory. It
does not add encryption or claim transcript confidentiality.

`run_device.py launch` starts a reproducible physical-device experiment, and
`run_device.py collect` retrieves the app's JSON observations. All device IDs
are supplied on the command line. `analyze.py` accepts only complete physical
iPhone 13 runs with valid native wire sizes and successful verification. It
keeps warmup observations and rejects incomplete runs rather than inventing
missing measurements. The automatic experiment enables Verify explicitly;
`--verify 0` tests the optional response-only path.

Timing separates native Store, synthetic input construction, wire encoding,
upload, native proof decoding, native Verify, and complete audit latency.
CPU time uses `getrusage`; memory is sampled process physical footprint at
5 ms intervals. Energy is not inferred from CPU time or battery percentage.
