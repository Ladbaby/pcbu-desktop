import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import PulseUnlock

ApplicationWindow {
    id: updaterWindow
    width: 440
    height: 260
    title: QI18n.Get('updater')
    flags: Qt.Dialog
    modality: Qt.ApplicationModal
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 25
        Label { text: QI18n.Get('update_available'); font.pointSize: 18 }
        Label { text: '%1: %2'.arg(QI18n.Get('your_version')).arg(UpdaterWindow.GetAppVersion()) }
        Label { text: '%1: %2'.arg(QI18n.Get('latest_version')).arg(UpdaterWindow.GetLatestVersion()) }
        Label { text: "Updates are downloaded and installed manually from GitHub."; wrapMode: Text.WordWrap; Layout.fillWidth: true }
        RowLayout {
            Button { text: "View GitHub releases"; onClicked: UpdaterWindow.OpenReleases() }
            Button { text: QI18n.Get('ignore'); onClicked: updaterWindow.close() }
        }
    }
}
