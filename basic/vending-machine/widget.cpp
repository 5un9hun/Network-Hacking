#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    setControl();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int coin)
{
    money += coin;
    ui->lcdNumber->display(money);
    setControl();
}

void Widget::setControl()
{
    ui->pbCoffee->setEnabled(money >= 200);
    ui->pbTea->setEnabled(money >= 150);
    ui->pbMilk->setEnabled(money >= 100);
}

void Widget::on_pnCoin500_clicked()
{
    changeMoney(500);
}

void Widget::on_pbCoin100_clicked()
{
    changeMoney(100);
}

void Widget::on_pbCoin50_clicked()
{
    changeMoney(50);
}


void Widget::on_pbCoin10_clicked()
{
    changeMoney(10);
}

void Widget::on_pbCoffee_clicked()
{
    changeMoney(-200);
}


void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
}


void Widget::on_pbMilk_clicked()
{
    changeMoney(-100);
}


void Widget::on_pbReset_clicked()
{
    QMessageBox resetResult;

    int coin[4] = {500, 100, 50, 10};
    int returnCoin[4] = { 0 };

    int i = 0;
    while(money >= 0 and i <= 3) {
        returnCoin[i] = (int)(money / coin[i]);
        money -= coin[i] * returnCoin[i];
        i++;
    }

    auto text = QString("500 coins : ").append(QString::number(returnCoin[0]));
    text += QString("\n100 coins : ").append(QString::number(returnCoin[1]));
    text += QString("\n50 coins : ").append(QString::number(returnCoin[2]));
    text += QString("\n10 coins : ").append(QString::number(returnCoin[3]));

    changeMoney(money);

    resetResult.setWindowTitle("Return Result");
    resetResult.setText(text);
    resetResult.exec();

}

