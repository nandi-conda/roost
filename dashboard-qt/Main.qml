// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc
//
// Roost dashboard: a read-only view of this PDS over its public XRPC API
// (describeServer, sync.listRepos, repo.describeRepo/listRecords, agentbus
// listAgents/listProcs). Refreshes every 30 seconds.
import QtQuick
import QtQuick.Layouts
import QtQuick.Shapes
import "Api.js" as Api

Window {
    id: app
    visible: true
    color: Theme.bg
    title: "Roost Dashboard"

    readonly property string base: pdsBase
    readonly property bool narrow: width < 640
    readonly property int refreshMs: 30000
    readonly property int recPage: 25

    property var server: null
    property var agents: []
    property var procs: []
    property bool loading: false
    property string repoError: ""
    property int tab: 0
    property string query: ""
    property double nowMs: Date.now()
    property int descVersion: 0      // bumped when a describeRepo lands

    // The open account and collection, and its page of records.
    property string selDid: ""
    property string coll: ""
    property var records: null       // listRecords body; null while loading
    property string recError: ""

    // Accounts sorted by last commit. colls is the describeRepo collections
    // as a JSON array string (ListModel roles can't hold JS arrays).
    ListModel { id: accounts }

    function xrpc(method, cb) { Api.getJson(base + "/xrpc/" + method, cb) }

    function loadAll() {
        if (loading)
            return
        loading = true
        repoError = ""
        nowMs = Date.now()
        xrpc("com.atproto.server.describeServer", function (j) { server = j })
        xrpc("org.latha.agentbus.listAgents?limit=100", function (j) { agents = j ? j.agents || [] : [] })
        xrpc("org.latha.agentbus.listProcs?limit=100", function (j) { procs = j ? j.procs || [] : [] })
        listRepos("", [])
    }

    function listRepos(cursor, acc) {
        var q = "com.atproto.sync.listRepos?limit=100" + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "")
        xrpc(q, function (j, err) {
            if (!j) {
                repoError = err
                loading = false
                return
            }
            var page = j.repos || []
            var all = acc.concat(page)
            if (page.length === 100 && j.cursor && all.length < 1000)
                return listRepos(j.cursor, all)
            setRepos(all)
            loading = false
        })
    }

    // Rebuild the model in recency order, keeping what describeRepo already
    // told us, then ask each repo for its handle and collections again.
    function setRepos(repos) {
        var old = {}
        for (var i = 0; i < accounts.count; i++)
            old[accounts.get(i).did] = { handle: accounts.get(i).handle, colls: accounts.get(i).colls, ncoll: accounts.get(i).ncoll }
        var rows = repos.map(function (r) {
            var o = old[r.did] || { handle: "", colls: "[]", ncoll: -1 }
            return { did: r.did, rev: r.rev || "", active: r.active !== false, when: Api.tidSecs(r.rev),
                     handle: o.handle, colls: o.colls, ncoll: o.ncoll, descError: "" }
        })
        rows.sort(function (a, b) { return b.when - a.when })
        accounts.clear()
        rows.forEach(function (r) { accounts.append(r) })
        rows.forEach(function (r) { describe(r.did) })
    }

    function rowOf(did) {
        for (var i = 0; i < accounts.count; i++)
            if (accounts.get(i).did === did)
                return i
        return -1
    }

    function describe(did) {
        xrpc("com.atproto.repo.describeRepo?repo=" + encodeURIComponent(did), function (j, err) {
            var i = rowOf(did)
            if (i < 0)
                return
            if (j) {
                accounts.setProperty(i, "handle", j.handle || "")
                accounts.setProperty(i, "colls", JSON.stringify(j.collections || []))
                accounts.setProperty(i, "ncoll", (j.collections || []).length)
                accounts.setProperty(i, "descError", "")
            } else {
                accounts.setProperty(i, "descError", err)
            }
            descVersion++
        })
    }

    function select(did) {
        selDid = selDid === did ? "" : did
        coll = ""
        records = null
    }

    function openCollection(c) {
        coll = c
        loadRecords("")
    }

    function loadRecords(cursor) {
        records = null
        recError = ""
        var want = selDid + " " + coll
        var q = "com.atproto.repo.listRecords?limit=" + recPage + "&repo=" + encodeURIComponent(selDid)
                + "&collection=" + encodeURIComponent(coll) + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "")
        xrpc(q, function (j, err) {
            if (want !== selDid + " " + coll)
                return
            if (j)
                records = j
            else
                recError = err
        })
    }

    function matches(handle, did) {
        var q = query.trim()
        return q === "" || handle.indexOf(q) >= 0 || did.indexOf(q) >= 0
    }

    function shownCount() {
        descVersion  // handles arrive with describeRepo
        var c = 0
        for (var i = 0; i < accounts.count; i++)
            if (matches(accounts.get(i).handle, accounts.get(i).did))
                c++
        return c
    }

    function totals() {
        descVersion  // re-evaluate when describeRepo answers land
        var t = { active: 0, colls: 0, latest: 0 }
        for (var i = 0; i < accounts.count; i++) {
            var a = accounts.get(i)
            if (a.active) t.active++
            if (a.ncoll > 0) t.colls += a.ncoll
            if (a.when > t.latest) t.latest = a.when
        }
        return t
    }

    function pdsls(what) { return "https://pdsls.dev/at://" + what }

    Component.onCompleted: loadAll()
    Timer { interval: app.refreshMs; running: true; repeat: true; onTriggered: app.loadAll() }

    // ---- small pieces

    component Label: Text {
        color: Theme.ink
        font.pixelSize: 15
        wrapMode: Text.Wrap
    }

    component Mono: TextEdit {
        color: Theme.ink
        font.family: Theme.mono
        font.pixelSize: 13
        readOnly: true
        selectByMouse: true
        wrapMode: TextEdit.WrapAnywhere
        selectionColor: Theme.gold
    }

    component Link: Text {
        id: link
        property string url
        property bool sameTab: false
        color: Theme.gold
        font.pixelSize: 15
        font.underline: true
        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: link.sameTab ? page.go(link.url) : page.open(link.url)
        }
    }

    component Button: Rectangle {
        id: btn
        property alias text: label.text
        property bool primary: false
        signal clicked()
        implicitWidth: label.implicitWidth + (primary ? 28 : 24)
        implicitHeight: label.implicitHeight + 12
        radius: 8
        color: primary ? Theme.ink : "transparent"
        border.color: hover.hovered ? Theme.gold : (primary ? Theme.ink : Theme.line)
        Text {
            id: label
            anchors.centerIn: parent
            color: btn.primary ? Theme.bg : Theme.ink
            font.pixelSize: 15
            font.weight: btn.primary ? Font.DemiBold : Font.Normal
        }
        HoverHandler { id: hover; cursorShape: Qt.PointingHandCursor }
        TapHandler { onTapped: btn.clicked() }
    }

    component Chip: Rectangle {
        id: chip
        property alias text: label.text
        property bool on: false
        property bool clickable: false
        signal clicked()
        implicitWidth: label.implicitWidth + 22
        implicitHeight: label.implicitHeight + 6
        radius: height / 2
        color: on ? Theme.surface : Theme.tile
        border.color: on || (clickable && hover.hovered) ? Theme.gold : Theme.line
        Text {
            id: label
            anchors.centerIn: parent
            color: Theme.ink
            font.family: Theme.mono
            font.pixelSize: 13
        }
        HoverHandler { id: hover; enabled: chip.clickable; cursorShape: Qt.PointingHandCursor }
        TapHandler { enabled: chip.clickable; onTapped: chip.clicked() }
    }

    component Chips: Flow {
        property var items: []
        spacing: 6
        visible: items.length > 0
        Repeater {
            model: parent.items
            Chip { required property var modelData; text: modelData }
        }
    }

    // Rounded border drawn over a box's children, masking the corners with
    // the page colour so child backgrounds don't poke past the curve.
    component Corners: Shape {
        id: corners
        property real radius: 12
        property color outside: Theme.bg
        anchors.fill: parent
        z: 10
        readonly property real r: radius
        readonly property real w: width
        readonly property real h: height
        ShapePath {
            fillColor: corners.outside; strokeColor: "transparent"
            PathSvg {
                path: {
                    var r = corners.r, w = corners.w, h = corners.h, a = " A " + r + " " + r + " 0 0 0 "
                    return "M0 0 L" + r + " 0" + a + "0 " + r + " Z"
                        + " M" + w + " 0 L" + w + " " + r + a + (w - r) + " 0 Z"
                        + " M" + w + " " + h + " L" + (w - r) + " " + h + a + w + " " + (h - r) + " Z"
                        + " M0 " + h + " L0 " + (h - r) + a + r + " " + h + " Z"
                }
            }
        }
        Rectangle {
            anchors.fill: parent
            color: "transparent"
            radius: corners.radius
            border.color: Theme.line
        }
    }

    component Stat: Rectangle {
        property string value
        property string label
        Layout.fillWidth: true
        implicitHeight: col.implicitHeight + 28
        color: Theme.surface
        border.color: Theme.line
        radius: 12
        Column {
            id: col
            x: 16
            y: 14
            Text { text: value; color: Theme.ink; font.pixelSize: app.narrow ? 22 : 26; font.weight: Font.DemiBold }
            Text { text: label; color: Theme.muted; font.pixelSize: 13 }
        }
    }

    component Logo: Item {
        implicitWidth: 36
        implicitHeight: 36
        Rectangle { anchors.fill: parent; radius: 5; color: "#15171C" }
        // rookery-icon.svg: three wing shapes and a gold beak, 64-unit box.
        Shape {
            anchors.fill: parent
            preferredRendererType: Shape.CurveRenderer
            transform: [
                Scale { xScale: 0.086 * 36 / 64; yScale: 0.086 * 36 / 64 },
                Translate { x: 5.25 * 36 / 64; y: -11.82 * 36 / 64 }
            ]
            ShapePath {
                fillColor: "#ECEAE4"; strokeColor: "transparent"
                PathSvg { path: "M564 309 L470 278 L418 278 L364 332 L462 433 L279 626 L376 725 L302 726 L288 741 L450 741 L437 726 L387 726 L351 647 L484 484 L484 330 Z" }
            }
            ShapePath {
                fillColor: "#ECEAE4"; strokeColor: "transparent"
                PathSvg { path: "M446 433 L369 355 L126 594 L343 539 Z" }
            }
            ShapePath {
                fillColor: "#ECEAE4"; strokeColor: "transparent"
                PathSvg { path: "M328 555 L169 595 L58 741 L158 741 Z" }
            }
            ShapePath {
                fillColor: "#F0B43C"; strokeColor: "transparent"
                PathSvg { path: "M443.5 295.2 L476.5 295.2 L460.0 311.7 Z" }
            }
        }
    }

    component Card: Rectangle {
        default property alias content: body.data
        property string name
        property string handle
        property string description
        Layout.fillWidth: true
        Layout.alignment: Qt.AlignTop
        implicitHeight: body.implicitHeight + 28
        color: Theme.surface
        border.color: Theme.line
        radius: 12
        ColumnLayout {
            id: body
            x: 16
            y: 14
            width: parent.width - 32
            spacing: 8
            Column {
                Layout.fillWidth: true
                Label { width: parent.width; text: name; font.weight: Font.Bold }
                Label { width: parent.width; text: handle; color: Theme.muted; font.pixelSize: 13; wrapMode: Text.WrapAnywhere }
            }
            Label { Layout.fillWidth: true; text: description; visible: description !== "" }
        }
    }

    // ---- page

    Flickable {
        id: scroller
        anchors.fill: parent
        contentWidth: width
        contentHeight: shell.implicitHeight + 72
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick

        ColumnLayout {
            id: shell
            x: Math.max(16, (scroller.width - 1080) / 2 + 16)
            y: 24
            width: Math.min(scroller.width, 1080) - 32
            spacing: 0

            // header
            GridLayout {
                Layout.fillWidth: true
                columns: app.narrow ? 1 : 2
                columnSpacing: 16
                rowSpacing: 12

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 12
                    Logo {
                        HoverHandler { cursorShape: Qt.PointingHandCursor }
                        TapHandler { onTapped: page.go(app.base + "/") }
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0
                        Text { text: "Roost"; color: Theme.ink; font.pixelSize: 22; font.bold: true }
                        Text {
                            Layout.fillWidth: true
                            color: Theme.muted
                            font.family: Theme.mono
                            font.pixelSize: 13
                            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                            text: app.server ? app.server.did + " · *." + (app.server.availableUserDomains || [""])[0] : "PDS dashboard"
                        }
                    }
                }

                RowLayout {
                    Layout.alignment: app.narrow ? Qt.AlignLeft : Qt.AlignRight
                    spacing: 12
                    Row {
                        spacing: 6
                        Rectangle {
                            width: 8; height: 8; radius: 4
                            anchors.verticalCenter: parent.verticalCenter
                            color: app.loading ? Theme.gold : Theme.live
                        }
                        Text {
                            text: app.loading ? "Loading…" : app.narrow ? "Live" : "Live · refreshes every 30s"
                            color: Theme.muted
                            font.pixelSize: 13
                        }
                    }
                    Button { text: "Refresh"; onClicked: app.loadAll() }
                    Button { text: "Sign up"; primary: true; onClicked: page.go(app.base + "/join") }
                }
            }

            // stats
            GridLayout {
                id: stats
                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.bottomMargin: 24
                columns: Math.max(1, Math.min(6, Math.floor((width + 12) / 152)))
                columnSpacing: 12
                rowSpacing: 12
                readonly property var t: app.totals()
                Stat { label: "accounts"; value: app.server && app.server.accounts !== undefined ? app.server.accounts : accounts.count }
                Stat { label: "active repos"; value: stats.t.active }
                Stat { label: "collections"; value: stats.t.colls }
                Stat { label: "agents"; value: app.agents.length }
                Stat { label: "procs"; value: app.procs.length }
                Stat { label: "last commit"; value: stats.t.latest > 0 ? Api.rel(stats.t.latest * 1000, app.nowMs) : "—" }
            }

            // tabs
            Item {
                Layout.fillWidth: true
                implicitHeight: tabs.implicitHeight
                Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Theme.line }
                Row {
                    id: tabs
                    spacing: 4
                    Repeater {
                        model: [["Accounts", accounts.count], ["Agents", app.agents.length], ["Procs", app.procs.length]]
                        Item {
                            required property var modelData
                            required property int index
                            readonly property bool on: app.tab === index
                            implicitWidth: tabRow.implicitWidth + 28
                            implicitHeight: tabRow.implicitHeight + 22
                            Row {
                                id: tabRow
                                anchors.centerIn: parent
                                spacing: 8
                                Text {
                                    text: modelData[0]
                                    color: on ? Theme.ink : Theme.muted
                                    font.pixelSize: 15
                                }
                                Rectangle {
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: countText.implicitWidth + 16
                                    height: countText.implicitHeight
                                    radius: height / 2
                                    color: Theme.tile
                                    Text { id: countText; anchors.centerIn: parent; text: modelData[1]; color: Theme.ink; font.pixelSize: 12 }
                                }
                            }
                            Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 2; color: on ? Theme.gold : "transparent" }
                            HoverHandler { cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: app.tab = index }
                        }
                    }
                }
            }

            // ---- accounts
            ColumnLayout {
                Layout.fillWidth: true
                Layout.topMargin: 16
                visible: app.tab === 0
                spacing: 12

                Rectangle {
                    Layout.fillWidth: true
                    Layout.maximumWidth: 360
                    implicitHeight: search.implicitHeight + 18
                    radius: 8
                    color: Theme.surface
                    border.color: search.activeFocus ? Theme.gold : Theme.line
                    border.width: search.activeFocus ? 2 : 1
                    TextInput {
                        id: search
                        anchors.fill: parent
                        anchors.leftMargin: 12
                        anchors.rightMargin: 12
                        verticalAlignment: TextInput.AlignVCenter
                        color: Theme.ink
                        font.pixelSize: 15
                        selectByMouse: true
                        selectionColor: Theme.gold
                        clip: true
                        onTextChanged: app.query = text
                        Keys.onEscapePressed: text = ""
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            visible: search.text === ""
                            text: "Filter by handle or DID"
                            color: Theme.muted
                            font.pixelSize: 15
                        }
                    }
                }

                Label {
                    visible: app.repoError !== ""
                    Layout.fillWidth: true
                    color: Theme.bad
                    text: "Couldn't list repos: " + app.repoError
                }

                Rectangle {
                    id: table
                    Layout.fillWidth: true
                    implicitHeight: rows.implicitHeight + 2
                    color: Theme.surface
                    clip: true
                    Corners { radius: 12 }

                    readonly property real wHandle: app.narrow ? width - wWhen - wColl - 2 : width * 0.34
                    readonly property real wWhen: app.narrow ? 96 : width * 0.18
                    readonly property real wColl: app.narrow ? 64 : width * 0.14
                    readonly property real wDid: app.narrow ? 0 : width - 2 - wHandle - wWhen - wColl

                    Column {
                        id: rows
                        x: 1
                        y: 1
                        width: parent.width - 2

                        Row {
                            height: 38
                            component Th: Text {
                                anchors.verticalCenter: parent.verticalCenter
                                leftPadding: app.narrow ? 10 : 14
                                rightPadding: leftPadding
                                color: Theme.muted
                                font.pixelSize: 12
                                font.weight: Font.DemiBold
                                font.letterSpacing: 0.5
                                font.capitalization: Font.AllUppercase
                            }
                            Th { width: table.wHandle; text: "Handle" }
                            Th { width: table.wDid; text: "DID"; visible: !app.narrow }
                            Th { width: table.wWhen; text: "Last commit" }
                            Th { width: table.wColl; text: app.narrow ? "Colls" : "Collections"; horizontalAlignment: Text.AlignRight }
                        }

                        Repeater {
                            model: accounts
                            Column {
                                id: acct
                                required property string did
                                required property string handle
                                required property bool active
                                required property double when
                                required property int ncoll
                                required property string colls
                                required property string descError
                                readonly property bool open: app.selDid === did
                                width: rows.width
                                visible: app.matches(handle, did)

                                Rectangle { width: parent.width; height: 1; color: Theme.line }

                                Rectangle {
                                    width: parent.width
                                    height: cells.implicitHeight + (app.narrow ? 16 : 20)
                                    color: acct.open || rowHover.hovered ? Theme.tile : "transparent"
                                    HoverHandler { id: rowHover; cursorShape: Qt.PointingHandCursor }
                                    TapHandler { onTapped: app.select(acct.did) }
                                    Row {
                                        id: cells
                                        anchors.verticalCenter: parent.verticalCenter
                                        readonly property real pad: app.narrow ? 10 : 14
                                        Flow {
                                            width: table.wHandle
                                            leftPadding: cells.pad
                                            rightPadding: cells.pad
                                            spacing: 8
                                            Text {
                                                width: Math.min(implicitWidth, table.wHandle - 2 * cells.pad)
                                                text: acct.handle !== "" ? acct.handle : "resolving…"
                                                color: acct.handle === "" || !acct.active ? Theme.muted : Theme.ink
                                                font.pixelSize: 15
                                                font.weight: acct.handle !== "" ? Font.Medium : Font.Normal
                                                wrapMode: Text.WrapAnywhere
                                            }
                                            Rectangle {
                                                visible: !acct.active
                                                width: badge.implicitWidth + 12
                                                height: badge.implicitHeight + 2
                                                radius: height / 2
                                                color: "transparent"
                                                border.color: Theme.line
                                                Text { id: badge; anchors.centerIn: parent; text: "inactive"; color: Theme.muted; font.pixelSize: 11 }
                                            }
                                        }
                                        Text {
                                            visible: !app.narrow
                                            width: table.wDid
                                            leftPadding: cells.pad
                                            rightPadding: cells.pad
                                            text: acct.did
                                            color: Theme.muted
                                            font.family: Theme.mono
                                            font.pixelSize: 13
                                            wrapMode: Text.WrapAnywhere
                                        }
                                        Text {
                                            width: table.wWhen
                                            leftPadding: cells.pad
                                            rightPadding: cells.pad
                                            text: acct.when > 0 ? Api.rel(acct.when * 1000, app.nowMs) : "—"
                                            color: Theme.ink
                                            font.pixelSize: 15
                                        }
                                        Text {
                                            width: table.wColl
                                            leftPadding: cells.pad
                                            rightPadding: cells.pad
                                            horizontalAlignment: Text.AlignRight
                                            text: acct.ncoll >= 0 ? acct.ncoll : ""
                                            color: Theme.ink
                                            font.pixelSize: 15
                                        }
                                    }
                                }

                                // detail
                                Loader {
                                    active: acct.open
                                    width: parent.width
                                    sourceComponent: Rectangle {
                                        width: parent ? parent.width : 0
                                        implicitHeight: detail.implicitHeight + 24
                                        color: Theme.bg
                                        Rectangle { width: parent.width; height: 1; color: Theme.line }
                                        ColumnLayout {
                                            id: detail
                                            x: 14
                                            y: 12
                                            width: parent.width - 28
                                            spacing: 12
                                            readonly property var collList: JSON.parse(acct.colls)

                                            Flow {
                                                Layout.fillWidth: true
                                                spacing: 12
                                                Mono { width: Math.min(implicitWidth, detail.width); text: acct.did }
                                                Link { text: "Open in pdsls ↗"; url: app.pdsls(acct.did) }
                                            }
                                            Label {
                                                Layout.fillWidth: true
                                                visible: acct.descError !== "" || acct.ncoll <= 0
                                                color: acct.descError !== "" ? Theme.bad : Theme.muted
                                                text: acct.descError !== "" ? acct.descError
                                                      : acct.ncoll < 0 ? "Loading repo…" : "No records yet."
                                            }
                                            Flow {
                                                Layout.fillWidth: true
                                                spacing: 6
                                                Repeater {
                                                    model: detail.collList
                                                    Chip {
                                                        required property string modelData
                                                        text: modelData
                                                        clickable: true
                                                        on: app.coll === modelData
                                                        onClicked: app.openCollection(modelData)
                                                    }
                                                }
                                            }
                                            Loader {
                                                Layout.fillWidth: true
                                                active: app.coll !== ""
                                                sourceComponent: recordsView
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Label {
                    visible: !app.loading && app.shownCount() === 0
                    color: Theme.muted
                    text: "No accounts match."
                }
            }

            // ---- agents and procs
            Label {
                Layout.fillWidth: true
                Layout.topMargin: 48
                Layout.bottomMargin: 32
                visible: (app.tab === 1 && app.agents.length === 0) || (app.tab === 2 && app.procs.length === 0)
                horizontalAlignment: Text.AlignHCenter
                color: Theme.muted
                text: app.tab === 1 ? "No agents have published an org.latha.agentbus.agent record yet."
                                    : "No procs have published an org.latha.agentbus.proc record yet."
            }

            GridLayout {
                Layout.fillWidth: true
                Layout.topMargin: 16
                visible: app.tab === 1
                columns: Math.max(1, Math.floor((width + 12) / 292))
                columnSpacing: 12
                rowSpacing: 12
                Repeater {
                    model: app.agents
                    Card {
                        required property var modelData
                        readonly property var v: modelData.value || {}
                        name: modelData.name || ""
                        handle: modelData.handle || ""
                        description: v.description || ""
                        Chips { Layout.fillWidth: true; items: v.capabilities || [] }
                        Chips { Layout.fillWidth: true; items: v.taskClasses || [] }
                        Label {
                            Layout.fillWidth: true
                            color: Theme.muted
                            font.pixelSize: 13
                            text: "indexed " + Api.relIso(modelData.indexedAt, app.nowMs)
                        }
                    }
                }
            }

            GridLayout {
                Layout.fillWidth: true
                Layout.topMargin: 16
                visible: app.tab === 2
                columns: Math.max(1, Math.floor((width + 12) / 292))
                columnSpacing: 12
                rowSpacing: 12
                Repeater {
                    model: app.procs
                    Card {
                        required property var modelData
                        readonly property var v: modelData.value || {}
                        name: modelData.name || ""
                        handle: modelData.handle || ""
                        description: v.description || ""
                        Chips { Layout.fillWidth: true; items: (v.provides || []).map(function (p) { return p["function"] || "" }) }
                        Chips { Layout.fillWidth: true; items: (v.publishes || []).map(function (p) { return p.topic || "" }) }
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                Layout.topMargin: 40
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                color: Theme.muted
                font.pixelSize: 13
                linkColor: Theme.gold
                textFormat: Text.StyledText
                text: "Read-only view of public XRPC · built with <a href=\"https://www.qt.io/\">Qt Quick</a> (C++/QML → wasm)"
                onLinkActivated: function (url) { page.open(url) }
                HoverHandler { cursorShape: parent.hoveredLink ? Qt.PointingHandCursor : Qt.ArrowCursor }
            }
        }
    }

    // Scroll bar for the page, since the canvas has no native one.
    Rectangle {
        visible: scroller.contentHeight > scroller.height
        anchors.right: parent.right
        anchors.rightMargin: 2
        width: 6
        radius: 3
        color: Theme.muted
        opacity: 0.4
        y: scroller.visibleArea.yPosition * scroller.height
        height: scroller.visibleArea.heightRatio * scroller.height
    }

    // The open collection's records, shown inside the account detail.
    Component {
        id: recordsView
        ColumnLayout {
            spacing: 10
            Label {
                visible: app.records === null
                Layout.fillWidth: true
                color: app.recError !== "" ? Theme.bad : Theme.muted
                text: app.recError !== "" ? app.recError : "Loading records…"
            }
            Repeater {
                model: app.records ? app.records.records || [] : []
                Rectangle {
                    required property var modelData
                    Layout.fillWidth: true
                    implicitHeight: rec.implicitHeight + 2
                    color: Theme.surface
                    clip: true
                    Corners { radius: 10 }
                    Column {
                        id: rec
                        x: 1
                        y: 1
                        width: parent.width - 2
                        Item {
                            width: parent.width
                            implicitHeight: Math.max(uri.implicitHeight, view.implicitHeight) + 16
                            Mono {
                                id: uri
                                x: 12
                                y: 8
                                width: parent.width - view.width - 36
                                color: Theme.muted
                                text: modelData.uri
                            }
                            Link {
                                id: view
                                x: parent.width - width - 12
                                y: 8
                                text: "view ↗"
                                url: app.pdsls(modelData.uri)
                            }
                        }
                        Rectangle { width: parent.width; height: 1; color: Theme.line }
                        Rectangle {
                            width: parent.width
                            height: Math.min(json.implicitHeight + 20, 280)
                            color: Theme.code
                            Flickable {
                                anchors.fill: parent
                                anchors.margins: 10
                                anchors.rightMargin: 12
                                contentHeight: json.implicitHeight
                                clip: true
                                interactive: contentHeight > height
                                boundsBehavior: Flickable.StopAtBounds
                                Mono {
                                    id: json
                                    width: parent.width
                                    text: JSON.stringify(modelData.value, null, 2)
                                }
                            }
                        }
                    }
                }
            }
            Label {
                visible: app.records !== null && (app.records.records || []).length === 0
                color: Theme.muted
                text: "Empty collection."
            }
            Button {
                visible: app.records !== null && !!app.records.cursor && (app.records.records || []).length === app.recPage
                text: "Next 25 →"
                onClicked: app.loadRecords(app.records.cursor)
            }
        }
    }
}
