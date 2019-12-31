#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <string.h>
#include "sm2operation.h"
#include <QDebug>

#define MAX_BUF 4096
#define SM2_CX_BUF 64

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->pushButton->setHidden(true);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pubk_textChanged(const QString &arg1)
{
    //qDebug() << arg1;
    //int len = arg1.length();
    //qDebug() << len;
    ui->pubkL->setNum(arg1.length());
}

void MainWindow::on_privk_textChanged(const QString &arg1)
{
    ui->privkL->setNum(arg1.length());

}

void MainWindow::on_plaintext_textChanged(const QString &arg1)
{
    ui->plaintextL->setNum(arg1.length());
}

void MainWindow::on_ciphertext_textChanged(const QString &arg1)
{
    ui->ciphertextL->setNum(arg1.length());
}

void MainWindow::on_pushButton_2_clicked()
{
    char C1x[SM2_CX_BUF+1]={0};
    char C1y[SM2_CX_BUF+1]={0};
    char C3[SM2_CX_BUF+1]={0};
    char C2[MAX_BUF]={0};
    char *p;
    char pubk[MAX_BUF] = {0};
    char privk[MAX_BUF] = {0};
    //
    QByteArray array;
    int ret;
    unsigned char in[MAX_BUF];
    int inL = MAX_BUF;
    unsigned char out[MAX_BUF];
    int outL = MAX_BUF;
    char answer[MAX_BUF];

    QString strPubk = ui->pubk->text();
    QString strPrivk = ui->privk->text();
    QString strCiphertext = ui->ciphertext->text();

//    if(strPubk.length()<128 ||
//            strPrivk.length()<64 ||
//            strCiphertext.length()<128)
//    {
//        QMessageBox::warning(this, tr(""), tr("data incorrect!"), nullptr,nullptr);
//        return ;
//    }

    array = strPubk.toLatin1();
    memcpy(pubk, array.data(), array.length());
    array = strPrivk.toLatin1();
    memcpy(privk, array.data(), array.length());

    //
    array = strCiphertext.toLatin1();
    p = array.data();
    memcpy(C1x,p,SM2_CX_BUF);
    p += 64;
    memcpy(C1y,p,SM2_CX_BUF);
    p += 64;
    memcpy(C3,p,SM2_CX_BUF);
    p += 64;
    memcpy(C2,p,array.length()-(p-array.data()));
//    qDebug() << C1x;
//    qDebug() << C1y;
//    qDebug() << C3;
//    qDebug() << C2;

    Sm2Opt *sm2Opt = new Sm2Opt();
//    EVP_PKEY_CTX *ctx = sm2Opt->importSm2(pubk,privk);
    EVP_PKEY_CTX *ctx = nullptr;
    ret= sm2Opt->importSm2_2(pubk,privk,&ctx);
    if(ctx==nullptr){
        if(ret == -1)
            QMessageBox::warning(this, "", "OpenSSL version error!",NULL,NULL);
        else
            QMessageBox::warning(this, "", "key incorrect!",NULL,NULL);
        return;
    }

    ret = sm2Opt->importSm2Ciphertext(C1x,C1y,C3,C2,in,&inL);
    if(ret==0){
        QMessageBox::warning(this, "error", "ciphertext incorrect!",NULL,NULL);
        return;
    }

    ret = sm2Opt->sm2Decrypt(ctx,in,inL,out,&outL);
    if(ret==0){
        QMessageBox::warning(this, "error", "decrypt incorrect!",NULL,NULL);
        return;
    }
    sm2Opt->bin2hex(out, outL, answer);
    ui->plaintext->setText(QString(answer));
}
