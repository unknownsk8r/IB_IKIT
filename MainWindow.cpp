#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QRegExpValidator>
#include <QMessageBox>
#include <QDebug>
#include <QString>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    reactToKeyLength();

    ui->encodeButton->setDisabled(true);
    ui->decodeButton->setDisabled(true);
    ui->keyLine->setValidator(new QRegExpValidator(QRegExp("[A-Za-z0-9\\d]+"), this));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::reactToKeyLength()
{
    if(ui->keyLine->text().length() < 16 )
    {
        ui->encodeButton->setDisabled(true);
        ui->decodeButton->setDisabled(true);
        ui->keyLine->setStyleSheet("QLineEdit { background-color : none; color : red; }");
    }
    else
    {
        rememberKey();
        ui->encodeButton->setEnabled(true);
        ui->decodeButton->setEnabled(true);
        ui->keyLine->setStyleSheet("QLineEdit { background-color : none; color : black; }");
    }
}

void MainWindow::encode()
{

    ByteArray text = splitQString(ui->firstTextField->toPlainText());

    ByteArray keyBA = splitKey(key);

    ByteArray enc;
    AES_Engine::encrypt(keyBA, text, enc);

    QString test;
    for (unsigned long i = 0; i < enc.size(); i+=2)
    {
        if(i+1 == enc.size())
            test.append(QChar(enc[i]<<8|0x00));
        else
            test.append(QChar(enc[i]<<8|enc[i+1]));
    }

    sendTo(MainWindow::right, test);
}

void MainWindow::decode()
{
    ByteArray text = splitQString(ui->secondTextField->toPlainText());

    ByteArray keyBA = splitKey(key);

    ByteArray dec;
    AES_Engine::decrypt(keyBA, text, dec);

    QString test;
    for (unsigned long i = 0; i < dec.size(); i+=2)
    {
        if(i+1 == dec.size())
            test.append(QChar(dec[i]<<8|0x00));
        else
            test.append(QChar(dec[i]<<8|dec[i+1]));
    }

    sendTo(MainWindow::left, test);
}

void MainWindow::rememberKey()
{
    QRegExp rool("^[a-zA-Z0-9]");
    if(!ui->keyLine->text().contains(rool)
       || ui->keyLine->text().length() <= 0)
    {
        QMessageBox temp(QMessageBox::Warning, "Warning", "This key is not valid.");
        temp.exec();
        return;
    }
    key = ui->keyLine->text();
}



void MainWindow::sendTo(int where, QString test)
{
    if(where == MainWindow::left)
    {
        ui->secondTextField->setPlaceholderText(ui->secondTextField->toPlainText());
        ui->secondTextField->setPlainText(test);
        ui->firstTextField->setPlainText(ui->secondTextField->toPlainText());
        ui->secondTextField->clear();
    }
    else if (where == MainWindow::right)
    {
        ui->firstTextField->setPlaceholderText(ui->firstTextField->toPlainText());
        ui->firstTextField->setPlainText(test);
        ui->secondTextField->setPlainText(ui->firstTextField->toPlainText());
        ui->firstTextField->clear();
    }
}

ByteArray MainWindow::splitQString(QString text)
{
    ByteArray result;
    for (int i = 0; i < (2*text.length()); ++i)
        if(i%2==0)
            //Берем значение из QString, сдвигаем его вправо на 1 байт. Остается старший байт.
            result.push_back(text[int(i/2)].unicode()>>8);
        else
            // Если последний бит содержит 0xf0, игонируем его. Это лишний бит при нечетном количестве
            if(!((i==2*text.length()-1)&&((text[int(i/2)].unicode()&0xff)==0xf0)))
                //С помощью побитового И оставляем только младший байт.
                result.push_back(text[int(i/2)].unicode()&0xff);

    return result;
}

ByteArray MainWindow::splitKey(QString key)
{
    ByteArray result;
    for (int i = 0; i < (2*key.length()); ++i)
        if(i%2==0)
            //Берем значение из QString, сдвигаем его вправо на 1 байт. Остается старший байт.
            result.push_back(key[int(i/2)].unicode()>>8);
        else
            //С помощью побитового И оставляем только младший байт.
            result.push_back(key[int(i/2)].unicode()&0xff);
    return result;
}






























