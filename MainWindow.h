#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include <iostream>
#include <AES_Engine.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void reactToKeyLength();
    void encode();
    void decode();
    void rememberKey();

private:
    enum {right, left};
    void toggleWidgets(bool toggle);
    void sendTo(int where, QString test);

    // Делители
    ByteArray splitQString(QString text);
    ByteArray splitKey(QString key);


    QString key;
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
