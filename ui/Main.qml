import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Obscura47 - QML application shell.
// The visible UI; all behaviour is delegated to the `backend` context object
// (see Backend in app.py), which drives the real network code.
ApplicationWindow {
    id: win
    width: 1040
    height: 720
    minimumWidth: 900
    minimumHeight: 600
    visible: true
    title: "Obscura47"
    color: "#0d1117"

    // ── Palette (matches the classic stylesheet) ──
    readonly property color bg:        "#0d1117"
    readonly property color rail:      "#0a0e14"
    readonly property color card:      "#161b22"
    readonly property color cardHi:    "#1c2333"
    readonly property color accent:    "#58a6ff"
    readonly property color accentDim: "#1f6feb"
    readonly property color green:     "#3fb950"
    readonly property color red:       "#f85149"
    readonly property color text:      "#c9d1d9"
    readonly property color textDim:   "#8b949e"
    readonly property color border:    "#30363d"

    property int page: 0
    readonly property var titles: ["Dashboard", "Sites", "Activity", "Settings"]
    readonly property bool connected: backend.connected
    readonly property color statusColor: backend.statusText === "Connected" ? green
                                        : backend.statusText === "Connecting…" ? accent
                                        : red

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#0e141d" }
            GradientStop { position: 1.0; color: "#0a0e14" }
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // ── Left navigation rail ──
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 210
            color: win.rail
            Rectangle { anchors.right: parent.right; width: 1; height: parent.height; color: win.border }

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 18
                spacing: 6

                Text { text: "OBSCURA47"; color: win.accent; font.pixelSize: 20; font.bold: true; font.letterSpacing: 1 }
                Text { text: "Anonymous Overlay"; color: win.textDim; font.pixelSize: 10 }
                Item { height: 22 }

                Repeater {
                    model: [
                        { label: "\u{1F4CA}  Dashboard", idx: 0 },
                        { label: "\u{1F310}  Sites",     idx: 1 },
                        { label: "\u{1F4DC}  Activity",  idx: 2 },
                        { label: "⚙️  Settings", idx: 3 }
                    ]
                    delegate: NavButton {
                        Layout.fillWidth: true
                        labelText: modelData.label
                        active: win.page === modelData.idx
                        onClicked: win.page = modelData.idx
                    }
                }

                Item { Layout.fillHeight: true }
                Text { text: "v3 · QML edition"; color: win.textDim; font.pixelSize: 10 }
            }
        }

        // ── Right side ──
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Top bar
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 72
                color: win.bg
                Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: win.border }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 28
                    anchors.rightMargin: 28
                    spacing: 12

                    Text { text: win.titles[win.page]; color: win.text; font.pixelSize: 22; font.bold: true }
                    Item { Layout.fillWidth: true }

                    // Status pill
                    Rectangle {
                        implicitHeight: 34
                        implicitWidth: pillRow.implicitWidth + 26
                        radius: 17
                        color: win.card
                        border.color: win.border; border.width: 1
                        RowLayout {
                            id: pillRow
                            anchors.centerIn: parent
                            spacing: 8
                            Rectangle {
                                width: 9; height: 9; radius: 4.5; color: win.statusColor
                                SequentialAnimation on opacity {
                                    running: win.connected; loops: Animation.Infinite
                                    NumberAnimation { from: 1.0; to: 0.3; duration: 900; easing.type: Easing.InOutSine }
                                    NumberAnimation { from: 0.3; to: 1.0; duration: 900; easing.type: Easing.InOutSine }
                                }
                            }
                            Text { text: backend.statusText; color: win.statusColor; font.pixelSize: 13; font.bold: true }
                        }
                    }

                    // Connect / Disconnect
                    Rectangle {
                        implicitHeight: 40
                        implicitWidth: cbl.implicitWidth + 40
                        radius: 10
                        property bool hov: cbArea.containsMouse
                        color: win.connected ? (hov ? win.red : "#6e2b2b")
                                             : (hov ? win.accent : win.accentDim)
                        Behavior on color { ColorAnimation { duration: 160 } }
                        scale: cbArea.pressed ? 0.97 : 1.0
                        Behavior on scale { NumberAnimation { duration: 90 } }
                        Text { id: cbl; anchors.centerIn: parent
                               text: win.connected ? "■  Disconnect" : "▶  Connect"
                               color: "white"; font.pixelSize: 14; font.bold: true }
                        MouseArea { id: cbArea; anchors.fill: parent; hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor; onClicked: backend.toggle() }
                    }
                }
            }

            // Page stack
            StackLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                currentIndex: win.page

                DashboardPage {}
                SitesPage {}
                ActivityPage {}
                SettingsPage {}
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //  Reusable components
    // ─────────────────────────────────────────────────────────────────

    component NavButton: Rectangle {
        property string labelText: ""
        property bool active: false
        signal clicked()
        implicitHeight: 42
        radius: 8
        color: active ? win.cardHi : (na.containsMouse ? win.card : "transparent")
        Behavior on color { ColorAnimation { duration: 120 } }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left; anchors.leftMargin: 14
            text: labelText
            color: active ? win.accent : (na.containsMouse ? win.text : win.textDim)
            font.pixelSize: 13; font.bold: active
        }
        MouseArea { id: na; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: parent.clicked() }
    }

    // A plain styled card. Place a single child laid out with
    // `anchors.fill: parent; anchors.margins: 16`.
    component Card: Rectangle {
        radius: 12
        color: win.card
        border.color: win.border; border.width: 1
    }

    component MetricCard: Rectangle {
        id: mc
        property string label: ""
        property int value: 0
        property color accentColor: win.accent
        Layout.fillWidth: true
        implicitHeight: 116
        radius: 12
        color: hov.hovered ? win.cardHi : win.card
        border.width: 1
        border.color: hov.hovered ? accentColor : win.border
        Behavior on color { ColorAnimation { duration: 180 } }
        Behavior on border.color { ColorAnimation { duration: 180 } }
        scale: hov.hovered ? 1.02 : 1.0
        Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
        property real shown: 0
        Behavior on shown { NumberAnimation { duration: 600; easing.type: Easing.OutCubic } }
        onValueChanged: shown = value
        ColumnLayout {
            anchors.centerIn: parent
            spacing: 2
            Text { Layout.alignment: Qt.AlignHCenter; text: Math.round(mc.shown)
                   color: mc.accentColor; font.pixelSize: 36; font.bold: true }
            Text { Layout.alignment: Qt.AlignHCenter; text: mc.label
                   color: win.textDim; font.pixelSize: 12 }
        }
        HoverHandler { id: hov }
    }

    component ActionButton: Rectangle {
        property string labelText: ""
        signal activated()
        Layout.fillWidth: true
        implicitHeight: 52
        radius: 9
        color: aa.containsMouse ? win.accentDim : win.cardHi
        border.color: aa.containsMouse ? win.accentDim : win.border
        border.width: 1
        Behavior on color { ColorAnimation { duration: 140 } }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            anchors.left: parent.left; anchors.leftMargin: 14
            anchors.right: parent.right; anchors.rightMargin: 12
            text: labelText; elide: Text.ElideRight
            color: aa.containsMouse ? "white" : win.text
            font.pixelSize: 13; font.weight: Font.Medium
        }
        MouseArea { id: aa; anchors.fill: parent; hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor; onClicked: parent.activated() }
    }

    // ─────────────────────────────────────────────────────────────────
    //  Pages
    // ─────────────────────────────────────────────────────────────────

    component DashboardPage: Flickable {
        contentHeight: dashCol.implicitHeight + 48
        clip: true
        ScrollBar.vertical: ScrollBar {}
        ColumnLayout {
            id: dashCol
            x: 28; y: 24; width: parent.width - 56
            spacing: 16

            // Status banner
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 64
                radius: 12; color: win.card
                border.width: 1
                border.color: win.connected ? Qt.rgba(win.green.r, win.green.g, win.green.b, 0.5) : win.border
                Behavior on border.color { ColorAnimation { duration: 300 } }
                RowLayout {
                    anchors.fill: parent; anchors.leftMargin: 18; anchors.rightMargin: 18; spacing: 12
                    Rectangle { width: 10; height: 10; radius: 5; color: win.statusColor }
                    Text { text: win.connected ? backend.statusText : "Disconnected"
                           color: win.statusColor; font.pixelSize: 16; font.bold: true }
                    Item { Layout.fillWidth: true }
                    Text { text: win.connected ? "Routing through the Obscura network"
                                               : "Press Connect, then open or publish from Sites"
                           color: win.textDim; font.pixelSize: 12 }
                }
            }

            // Metrics
            RowLayout {
                Layout.fillWidth: true; spacing: 16
                MetricCard { label: "Relay Nodes"; value: backend.relays;  accentColor: win.accent }
                MetricCard { label: "Healthy";     value: backend.healthy; accentColor: win.green  }
                MetricCard { label: "Exit Nodes";  value: backend.exits;   accentColor: win.accent }
            }

            // Role
            Card {
                Layout.fillWidth: true
                implicitHeight: 70
                ColumnLayout {
                    anchors.fill: parent; anchors.margins: 16; spacing: 4
                    Text { text: "Node Role"; color: win.text; font.pixelSize: 13; font.bold: true }
                    Text { text: backend.roleText; color: win.textDim; font.pixelSize: 12 }
                }
            }

            // Components
            Card {
                Layout.fillWidth: true
                implicitHeight: compCol.implicitHeight + 32
                ColumnLayout {
                    id: compCol
                    anchors.fill: parent; anchors.margins: 16; spacing: 10
                    Text { text: "Components"; color: win.text; font.pixelSize: 13; font.bold: true }
                    ComponentRow { compName: "Local Proxy"
                        compDesc: "Browse anonymously via 127.0.0.1:9047"; on: backend.proxyRunning }
                    ComponentRow { compName: "Relay Node"
                        compDesc: "Forward encrypted traffic for the network"; on: backend.nodeRunning }
                }
            }

            // Request exit
            Rectangle {
                Layout.alignment: Qt.AlignLeft
                implicitHeight: 38; implicitWidth: rxl.implicitWidth + 32
                radius: 9; color: "transparent"
                border.color: win.border; border.width: 1
                Text { id: rxl; anchors.centerIn: parent; text: "Request Exit Node Status"
                       color: rxa.containsMouse ? win.text : win.textDim; font.pixelSize: 12 }
                MouseArea { id: rxa; anchors.fill: parent; hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor; onClicked: backend.requestExit() }
            }
        }
    }

    component ComponentRow: Rectangle {
        property string compName: ""
        property string compDesc: ""
        property bool on: false
        Layout.fillWidth: true
        implicitHeight: 50
        radius: 9; color: win.cardHi
        RowLayout {
            anchors.fill: parent; anchors.leftMargin: 14; anchors.rightMargin: 14
            ColumnLayout {
                spacing: 1
                Text { text: compName; color: win.text; font.pixelSize: 13; font.bold: true }
                Text { text: compDesc; color: win.textDim; font.pixelSize: 11 }
            }
            Item { Layout.fillWidth: true }
            Text { text: on ? "● Running" : "● Stopped"
                   color: on ? win.green : win.textDim; font.pixelSize: 12 }
        }
    }

    component SitesPage: Flickable {
        contentHeight: sitesCol.implicitHeight + 48
        clip: true
        ScrollBar.vertical: ScrollBar {}
        ColumnLayout {
            id: sitesCol
            x: 28; y: 24; width: parent.width - 56
            spacing: 16
            Card {
                Layout.fillWidth: true
                implicitHeight: gsCol.implicitHeight + 32
                ColumnLayout {
                    id: gsCol
                    anchors.fill: parent; anchors.margins: 16; spacing: 6
                    Text { text: "Getting Started"; color: win.text; font.pixelSize: 13; font.bold: true }
                    Text { Layout.fillWidth: true; wrapMode: Text.WordWrap
                           text: "Open, discover, or publish .obscura sites. To browse, route your "
                                 + "browser through the local Obscura proxy at 127.0.0.1:9047."
                           color: win.textDim; font.pixelSize: 12 }
                }
            }
            Card {
                Layout.fillWidth: true
                implicitHeight: gridCol.implicitHeight + 32
                ColumnLayout {
                    id: gridCol
                    anchors.fill: parent; anchors.margins: 16; spacing: 10
                    Text { text: "Quick Actions"; color: win.text; font.pixelSize: 13; font.bold: true }
                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2; columnSpacing: 10; rowSpacing: 10
                        ActionButton { labelText: "ℹ️  Quick Start";          onActivated: backend.quickStart() }
                        ActionButton { labelText: "\u{1F517}  Open .obscura Address";   onActivated: backend.openAddress() }
                        ActionButton { labelText: "\u{1F310}  Discover Sites";          onActivated: backend.discover() }
                        ActionButton { labelText: "\u{1F4C2}  Browse Directory";        onActivated: backend.browseDirectory() }
                        ActionButton { labelText: "\u{1F4CB}  My Hosted Sites";         onActivated: backend.hostedSites() }
                        ActionButton { labelText: "➕  Add Site";                   onActivated: backend.addSite() }
                        ActionButton { labelText: "\u{1F4E4}  Publish Site";            onActivated: backend.publishSite() }
                        ActionButton { labelText: "\u{1F5D1}️  Remove Site";       onActivated: backend.removeSite() }
                        ActionButton { labelText: "\u{1FA7A}  Diagnose Connection";     onActivated: backend.diagnose() }
                    }
                }
            }
        }
    }

    component ActivityPage: Item {
        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 28
            spacing: 12
            Text { text: "Activity Log"; color: win.text; font.pixelSize: 13; font.bold: true }
            Rectangle {
                Layout.fillWidth: true; Layout.fillHeight: true
                radius: 12; color: win.card; border.color: win.border; border.width: 1
                ScrollView {
                    id: logScroll
                    anchors.fill: parent; anchors.margins: 10
                    clip: true
                    TextArea {
                        id: logArea
                        readOnly: true; wrapMode: TextArea.Wrap
                        color: win.textDim
                        font.family: "Consolas, Menlo, monospace"; font.pixelSize: 12
                        background: null
                        onTextChanged: cursorPosition = length
                    }
                }
                Connections {
                    target: backend
                    function onLogLine(line) { logArea.text += (logArea.text ? "\n" : "") + line }
                }
            }
        }
    }

    component SettingsPage: Flickable {
        contentHeight: setCol.implicitHeight + 48
        clip: true
        ScrollBar.vertical: ScrollBar {}
        ColumnLayout {
            id: setCol
            x: 28; y: 24; width: parent.width - 56
            spacing: 16
            Card {
                Layout.fillWidth: true
                implicitHeight: startCol.implicitHeight + 32
                ColumnLayout {
                    id: startCol
                    anchors.fill: parent; anchors.margins: 16; spacing: 14
                    Text { text: "Startup"; color: win.text; font.pixelSize: 13; font.bold: true }
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Start Obscura47 on login"; color: win.text; font.pixelSize: 13 }
                        Item { Layout.fillWidth: true }
                        Switch {
                            checked: backend.autostartEnabled
                            onToggled: backend.setAutostart(checked)
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Start minimized and auto-connect"; color: win.text; font.pixelSize: 13 }
                        Item { Layout.fillWidth: true }
                        Switch {
                            checked: backend.startMinimizedEnabled
                            onToggled: backend.setStartMinimized(checked)
                        }
                    }
                }
            }
            Card {
                Layout.fillWidth: true
                implicitHeight: aboutCol.implicitHeight + 32
                ColumnLayout {
                    id: aboutCol
                    anchors.fill: parent; anchors.margins: 16; spacing: 6
                    Text { text: "About"; color: win.text; font.pixelSize: 13; font.bold: true }
                    Text { Layout.fillWidth: true; wrapMode: Text.WordWrap
                           text: "Obscura47 - Anonymous Overlay Network. Join as a relay node and "
                                 + "browse anonymously through the local proxy. Exit node status "
                                 + "requires admin approval."
                           color: win.textDim; font.pixelSize: 12 }
                }
            }
        }
    }
}
