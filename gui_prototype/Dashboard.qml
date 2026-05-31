import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Obscura47 dashboard preview - pure Qt Quick, no extra modules.
// Reads live state from the `backend` context object set in dashboard_qml.py.
ApplicationWindow {
    id: win
    width: 1000
    height: 700
    minimumWidth: 860
    minimumHeight: 600
    visible: true
    title: "Obscura47 - QML preview"
    color: "#0d1117"

    // ── Palette (matches the QWidgets app) ──
    readonly property color bg:       "#0d1117"
    readonly property color card:     "#161b22"
    readonly property color cardHi:   "#1c2333"
    readonly property color accent:   "#58a6ff"
    readonly property color accentDim:"#1f6feb"
    readonly property color green:    "#3fb950"
    readonly property color red:      "#f85149"
    readonly property color text:     "#c9d1d9"
    readonly property color textDim:  "#8b949e"
    readonly property color border:   "#30363d"

    readonly property bool connected: backend.connected
    readonly property color statusColor: backend.statusText === "Connected" ? green
                                        : backend.statusText === "Connecting…" ? accent
                                        : red

    // Soft top-down background gradient for a bit of depth.
    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: "#0e141d" }
            GradientStop { position: 1.0; color: "#0a0e14" }
        }
    }

    // Whole view fades + slides in on load.
    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: 28
        spacing: 20
        opacity: 0
        y: 12
        Component.onCompleted: { content.opacity = 1; content.y = 0 }
        Behavior on opacity { NumberAnimation { duration: 420; easing.type: Easing.OutCubic } }
        Behavior on y { NumberAnimation { duration: 420; easing.type: Easing.OutCubic } }

        // ── Header ──
        RowLayout {
            Layout.fillWidth: true
            spacing: 14

            ColumnLayout {
                spacing: 0
                Text { text: "OBSCURA47"; color: win.accent; font.pixelSize: 24; font.bold: true; font.letterSpacing: 1 }
                Text { text: "Anonymous Overlay Network"; color: win.textDim; font.pixelSize: 12 }
            }

            Item { Layout.fillWidth: true }

            // Status pill
            Rectangle {
                implicitHeight: 34
                implicitWidth: pillRow.implicitWidth + 28
                radius: 17
                color: win.card
                border.color: win.border
                border.width: 1
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

            // Connect / Disconnect button
            Rectangle {
                id: connectBtn
                implicitHeight: 40
                implicitWidth: btnLabel.implicitWidth + 44
                radius: 10
                property bool hovered: btnArea.containsMouse
                color: win.connected
                       ? (hovered ? win.red : "#6e2b2b")
                       : (hovered ? win.accent : win.accentDim)
                Behavior on color { ColorAnimation { duration: 160 } }
                scale: btnArea.pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 90 } }

                Text {
                    id: btnLabel
                    anchors.centerIn: parent
                    text: win.connected ? "■  Disconnect" : "▶  Connect"
                    color: "white"; font.pixelSize: 14; font.bold: true
                }
                MouseArea {
                    id: btnArea
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: backend.toggle()
                }
            }
        }

        // ── Status banner ──
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 64
            radius: 12
            color: win.card
            border.color: win.connected ? Qt.rgba(win.green.r, win.green.g, win.green.b, 0.5) : win.border
            border.width: 1
            Behavior on border.color { ColorAnimation { duration: 300 } }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 18
                anchors.rightMargin: 18
                spacing: 12
                Rectangle { width: 10; height: 10; radius: 5; color: win.statusColor }
                Text {
                    text: win.connected ? backend.statusText : "Disconnected"
                    color: win.statusColor; font.pixelSize: 16; font.bold: true
                }
                Item { Layout.fillWidth: true }
                Text {
                    text: win.connected
                          ? "Routing through the Obscura network"
                          : "Press Connect to join the network"
                    color: win.textDim; font.pixelSize: 12
                }
            }
        }

        // ── Metric cards ──
        RowLayout {
            Layout.fillWidth: true
            spacing: 16
            MetricCard { label: "Relay Nodes"; value: backend.relays;  accentColor: win.accent }
            MetricCard { label: "Healthy";     value: backend.healthy; accentColor: win.green  }
            MetricCard { label: "Exit Nodes";  value: backend.exits;   accentColor: win.accent }
        }

        // ── Node role ──
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 78
            radius: 12
            color: win.card
            border.color: win.border
            border.width: 1
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 16
                spacing: 4
                Text { text: "Node Role"; color: win.text; font.pixelSize: 13; font.bold: true }
                Text { text: backend.roleText; color: win.textDim; font.pixelSize: 12 }
            }
        }

        Item { Layout.fillHeight: true }

        Text {
            text: "QML preview · the network code is the real thing"
            color: win.textDim; font.pixelSize: 11
        }
    }

    // ── Reusable animated metric card ──
    component MetricCard: Rectangle {
        id: cardRoot
        property string label: ""
        property int value: 0
        property color accentColor: win.accent

        Layout.fillWidth: true
        implicitHeight: 118
        radius: 12
        color: hover.hovered ? win.cardHi : win.card
        border.width: 1
        border.color: hover.hovered ? accentColor : win.border
        Behavior on color { ColorAnimation { duration: 180 } }
        Behavior on border.color { ColorAnimation { duration: 180 } }
        scale: hover.hovered ? 1.02 : 1.0
        Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }

        // Animate the displayed number toward the live value (count-up).
        property real shown: 0
        Behavior on shown { NumberAnimation { duration: 600; easing.type: Easing.OutCubic } }
        onValueChanged: shown = value

        ColumnLayout {
            anchors.centerIn: parent
            spacing: 2
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: Math.round(cardRoot.shown)
                color: cardRoot.accentColor
                font.pixelSize: 38; font.bold: true
            }
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: cardRoot.label
                color: win.textDim; font.pixelSize: 12
            }
        }

        HoverHandler { id: hover }
    }
}
