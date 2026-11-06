// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc
//
// Roost dashboard entry point: reads the PDS base URL and colour scheme from
// the page, then loads Main.qml.

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QDesktopServices>
#include <QUrl>

#ifdef Q_OS_WASM
#include <emscripten/val.h>
#endif

static QString pdsBase()
{
    QString base;
#ifdef Q_OS_WASM
    using emscripten::val;
    val loc = val::global("location");
    base = QString::fromStdString(loc["origin"].as<std::string>());
    val q = val::global("URLSearchParams").new_(loc["search"]).call<val>("get", std::string("pds"));
    if (q.isString()) {
        QString s = QString::fromStdString(q.as<std::string>());
        if (s.startsWith("https://") || s.startsWith("http://"))
            base = s;
    }
#else
    base = qEnvironmentVariable("ROOST_PDS", "https://roost.latha.org");
#endif
    while (base.endsWith('/'))
        base.chop(1);
    return base;
}

static bool prefersDark()
{
#ifdef Q_OS_WASM
    using emscripten::val;
    return val::global("window").call<val>("matchMedia", std::string("(prefers-color-scheme: dark)"))["matches"].as<bool>();
#else
    return qEnvironmentVariableIsSet("ROOST_DARK");
#endif
}

// Browser navigation for links: go() follows in this tab, open() in a new one.
class Page : public QObject
{
    Q_OBJECT
public:
    Q_INVOKABLE void go(const QString &url)
    {
#ifdef Q_OS_WASM
        emscripten::val::global("location").call<void>("assign", url.toStdString());
#else
        QDesktopServices::openUrl(QUrl(url));
#endif
    }
    Q_INVOKABLE void open(const QString &url)
    {
#ifdef Q_OS_WASM
        emscripten::val::global("window").call<emscripten::val>("open", url.toStdString(), std::string("_blank"),
                                                                std::string("noopener"));
#else
        QDesktopServices::openUrl(QUrl(url));
#endif
    }
};

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("pdsBase", pdsBase());
    Page page;
    engine.rootContext()->setContextProperty("page", &page);
    engine.singletonInstance<QObject *>("Roost", "Theme")->setProperty("dark", prefersDark());
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                     [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
    engine.loadFromModule("Roost", "Main");
    return app.exec();
}

#include "main.moc"
