// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc
//
// Palette shared with the landing page and the HTML dashboard's style.css.
pragma Singleton
import QtQuick

QtObject {
    property bool dark: false

    readonly property color bg: dark ? "#111317" : "#F6F5F1"
    readonly property color surface: dark ? "#181B21" : "#FFFFFF"
    readonly property color ink: dark ? "#ECEAE4" : "#15171C"
    readonly property color muted: dark ? "#9AA0AC" : "#5C606B"
    readonly property color line: dark ? "#2A2E37" : "#E2DFD7"
    readonly property color code: dark ? "#1F232A" : "#EFEDE7"
    readonly property color gold: dark ? "#F0B43C" : "#B8841F"
    readonly property color tile: dark ? "#1E2128" : "#ECEAE4"
    readonly property color bad: dark ? "#F07A66" : "#B3402E"
    readonly property color live: "#3FA36B"

    readonly property string mono: "DejaVu Sans Mono"
}
