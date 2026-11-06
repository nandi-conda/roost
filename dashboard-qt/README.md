# Roost dashboard (Qt for WebAssembly)

The same read-only dashboard as `dashboard/` (accounts sorted by last commit,
each repo's collections and records, agentbus agents and procs, a 30 second
refresh), rebuilt as a Qt Quick app compiled to WebAssembly. The Worker serves
it from static assets at `/dashboard/qt/`; `/dashboard/` is still the ultra
build until this one replaces it.

- `main.cpp`: reads the PDS base URL (`location.origin`, or `?pds=https://…`)
  and the colour scheme from the page, exposes `page.go()` / `page.open()` for
  links, and loads `Main.qml`.
- `Main.qml`: the whole UI and its state. Talks to public XRPC with
  `XMLHttpRequest`; nothing is authenticated.
- `Theme.qml`: the palette shared with the landing page and `style.css`.
- `Api.js`: JSON GETs, TID to unix time, relative dates.
- `public/dashboard/qt/`: what gets served: `index.html` (boot screen and
  `qtLoad`), plus the build outputs `roostdash.wasm`, `roostdash.js` and
  `qtloader.js`, committed so deploys don't need the Qt toolchain.

It links only QtQuick, QtQuick.Layouts and QtQuick.Shapes (no Controls), so the
module is about 19 MB, 6.6 MB gzipped, under the 25 MiB Workers asset cap.

## Build

Qt 6.8.3 for WebAssembly needs emscripten 3.1.56 and a desktop Qt of the same
version for the host tools:

```sh
pip install aqtinstall
aqt install-qt linux desktop 6.8.3 linux_gcc_64 -O ~/Qt
aqt install-qt all_os wasm 6.8.3 wasm_singlethread -O ~/Qt
git clone https://github.com/emscripten-core/emsdk ~/emsdk
~/emsdk/emsdk install 3.1.56 && ~/emsdk/emsdk activate 3.1.56
source ~/emsdk/emsdk_env.sh

~/Qt/6.8.3/wasm_singlethread/bin/qt-cmake -S dashboard-qt -B dashboard-qt/build -G Ninja \
  -DCMAKE_BUILD_TYPE=MinSizeRel -DQT_HOST_PATH=$HOME/Qt/6.8.3/gcc_64
cmake --build dashboard-qt/build
cp dashboard-qt/build/roostdash.{wasm,js} dashboard-qt/build/qtloader.js public/dashboard/qt/
```

(If aqt leaves the Qt tools without the execute bit, `chmod +x ~/Qt/6.8.3/*/bin/* ~/Qt/6.8.3/*/libexec/*`.)

## Run locally

`python3 dashboard/dev.py` serves `public/dashboard/` and forwards `/xrpc/*`
to the live PDS, so this build is at http://localhost:8123/qt/.

## Licences

The dashboard source is MIT like the rest of Roost. The served wasm statically
links Qt (open source under LGPLv3); `qtloader.js` is Qt's loader under
GPL-3.0. This directory holds everything needed to rebuild and relink it.
