# iPhone client

The phone performs owner Setup, Store, and Challenge. The cloud server runs
ProofGen. Local Verify is optional and explicitly enabled for the benchmark.
The client supports MultiAudit, MPA, and Yu's protocol.

## Build and run

Requires macOS, Xcode, Go, a signing team, and an iPhone with Developer Mode enabled.

```sh
zsh mobile/build.sh iphoneos
xcodebuild -project mobile/MultiAudit.xcodeproj -scheme MultiAudit \
  -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' \
  -derivedDataPath /private/tmp/multiaudit-ios DEVELOPMENT_TEAM=YOUR_TEAM build
go run ./mobile/server -listen :8788 -out /private/tmp/multiaudit-server
```

Install the built app using `xcrun devicectl device install app`. Configure the
server URL and the account token written to the server's output directory.
The phone and server need a working IP network connection. Owner setup and
signing secrets stay on the phone. The experiment uses local HTTP with synthetic data.

## Measurements

`python3 mobile/run_device.py --help` lists the launch and collection options.
`python3 mobile/analyze.py --help` lists validation and summary options.

The current Fig. 7 measurement processes forty nominal 10 MB files per protocol, then runs three warmups
and 30 audits. Store measures native tagging and tree construction. Client Verify
includes decoding and the Swift/Go interface but excludes network waiting.
The 40-file results are stored in `experiments/results/paper/mobile/m40/`;
the earlier 10-file measurements remain in the parent directory.
Launch with `--files 40 --repeats 30 --warmups 3 --verify 1`.
