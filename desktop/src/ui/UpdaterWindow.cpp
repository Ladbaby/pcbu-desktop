#include "UpdaterWindow.h"
#include <QDesktopServices>
#include <QPointer>
#include <QUrl>
#include <QVariant>
#include "storage/AppSettings.h"
#include "utils/AppInfo.h"
#include "utils/RestClient.h"

UpdaterWindow::~UpdaterWindow() {
  if(m_CheckThread.joinable()) m_CheckThread.join();
}
QString UpdaterWindow::GetAppVersion() { return QString::fromUtf8(AppInfo::GetVersion()); }
QString UpdaterWindow::GetLatestVersion() {
  std::lock_guard lock(m_VersionMutex);
  return m_LatestVersion;
}
void UpdaterWindow::CheckForUpdates(QObject *window, bool manual) {
  if(!manual && !AppSettings::Get().automaticUpdateChecks) return;
  if(m_Checking.exchange(true)) return;
  if(m_CheckThread.joinable()) m_CheckThread.join();
  QPointer<QObject> target(window);
  try {
    m_CheckThread = std::thread([this, target, manual]() {
      QString message;
      bool newer = false;
      try {
        auto version = RestClient::CheckForUpdates();
        {
          std::lock_guard lock(m_VersionMutex);
          m_LatestVersion = QString::fromStdString(version);
        }
        newer = !version.empty() && AppInfo::CompareVersion(AppInfo::GetVersion(), version) == 1;
        message = version.empty() ? QStringLiteral("No stable release is published yet.") : QStringLiteral("No newer stable release is available.");
      } catch(...) {
        message = QStringLiteral("Could not check GitHub releases. Try again later.");
      }
      QMetaObject::invokeMethod(this, [this, target, newer, manual, message]() {
        m_Checking = false;
        if(!target) return;
        if(newer) QMetaObject::invokeMethod(target.data(), "showUpdaterWindow");
        else if(manual) QMetaObject::invokeMethod(target.data(), "showUpdateCheckResult", Q_ARG(QVariant, QVariant(message)));
      }, Qt::QueuedConnection);
    });
  } catch(...) {
    m_Checking = false;
    throw;
  }
}
void UpdaterWindow::OpenReleases() {
  QDesktopServices::openUrl(QUrl(QStringLiteral("https://github.com/Ladbaby/pcbu-desktop/releases")));
}
