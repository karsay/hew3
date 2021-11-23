#-*- coding: utf-8 -*-
from os import stat_result
from typing import Text
from kivy.core.window import Window
# Window.fullscreen = 'auto'
Window.size = (1680, 960)

from kivy.app import App
from kivy.uix.widget import Widget
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.progressbar import ProgressBar
from kivy.uix.togglebutton import ToggleButton
from kivy.uix.accordion import Accordion, AccordionItem
from kivy.clock import Clock
from kivy.properties import NumericProperty

from kivy.properties import StringProperty, ListProperty
from kivy.event import EventDispatcher

from kivy.uix.scatterlayout import ScatterLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.config import Config

from kivy.factory import Factory
# kvファイルを画面ごとに分離してバラで読み込む
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen

import japanize_kivy
import subprocess
import random
import threading
import time
import re

#　レイアウトファイルの読み込み
Builder.load_file('DatabaseWindow.kv')
Builder.load_file('InformationWindow.kv')
Builder.load_file('NetworkWindow.kv')
Builder.load_file('VulnerabilityWindow.kv')
Builder.load_file('WebWindow.kv')

class MainWindow(EventDispatcher):
    address = StringProperty()
    macaddress = StringProperty()
    hostName = StringProperty()
    OS = StringProperty()
    service = StringProperty()

class Pentest(Widget):

    # 共有データクラス
    mainWindow = MainWindow()

    cmdText = StringProperty()

    loadingFlag = False

    nodes = [
        # {
        #     "id":"0",
        #     "address":"192.168.1.1",
        #     "hostname":"hogehoge-router",
        #     "os":"hogeOS",
        #     "service":"""
        #     22/tcp open ssh
        #     25/tcp open smtp
        #     """
        #     "type":""
        # },
    ]

    def __init__(self, **kwargs):
        super(Pentest, self).__init__(**kwargs)

        # 初期化処理
        Clock.schedule_once(self.initPentest)

    # 初期化処理
    def initPentest(self,data):

        # 起動時に各画面を作成して使い回す
        self.infoWindow = Factory.InformationWindow()
        self.databaseWindow = Factory.DatabaseWindow()
        self.networkWindow = Factory.NetworkWindow()
        self.webWindow = Factory.WebWindow()
        self.vulnWindow = Factory.VulnerabilityWindow()

        self.ids["center_box"].ids["main_window"].add_widget(self.infoWindow)

        # メニューの初期化
        self.accordion = Accordion(orientation='vertical')
        #Accodionの中身を定義
        backColors = [
            (1,0,0,0.3),
            (0,1,0,0.3),
            (0,0,1,0.3),
            (1,1,0,0.3),
            (0,1,1,0.3),
            ]
        titles = [
            "スキャン",
            "パケット",
            "コントロール",
            "エクスプロイト",
            "その他",
        ]
        menuImages = [
            "images/menu/menu5.png",
            "images/menu/menu4.png",
            "images/menu/menu3.png",
            "images/menu/menu2.png",
            "images/menu/menu1.png",
        ]
        menuItems = [
            ["ネットワークスキャン","簡易スキャン","詳細スキャン","WiFiスキャン","脆弱性スキャン","WordPressスキャン","SQLスキャン"],
            ["メニュー","メニュー","メニュー","メニュー","メニュー","メニュー","メニュー"],
            ["メニュー","メニュー","メニュー"],
            ["メニュー","メニュー","メニュー","メニュー","メニュー","メニュー","メニュー","メニュー"],
            ["load","load1","load2","load3","load4","load5","load6","load7","?"],
        ]
        # メニューアイテムを生成
        for x in range(len(menuItems)):
            item = AccordionItem(title=titles[x],background_normal=menuImages[x])
            layout = BoxLayout(orientation='vertical')
            for i in range(len(menuItems[x])):
                if x == 4:
                    layout.add_widget(Button(text=menuItems[x][i],
                        background_color=backColors[x],
                        on_press=self.changeLoad
                        ))
                else:
                    layout.add_widget(Button(text=menuItems[x][i],
                                        background_color=backColors[x],
                                        ))
            item.add_widget(layout)
            self.accordion.add_widget(item)

        self.ids["left_box"].ids["menu"].add_widget(self.accordion)

        # セットアップ
        self.cmdText += "\n====================================\n"
        self.cmdText += "初期セットアップ開始"
        self.cmdText += "\n====================================\n"

        setupThread = threading.Thread(target=self.setup)
        loadThread = threading.Thread(target=self.loading)
        setupThread.start()
        loadThread.start()

    # cmd群のセットアップ
    def setup(self):
        # 自端末の情報取得
        self.cmdText += "\n====================================\n"
        self.cmdText += "自端末の情報取得中..."
        self.cmdText += "\n====================================\n"
        time.sleep(1)
        # アドレス情報
        proc = subprocess.run("ifconfig | grep 'inet' ",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.cmdText += "\n" + proc.stdout + "\n"
        myAddress = re.search(r'[10,192]+(?:\.[0-9]+){3}', proc.stdout).group()
        time.sleep(1)
        # hostname情報
        proc = subprocess.run("hostname",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        myHostname = proc.stdout
        self.cmdText += "\n" + proc.stdout + "\n"
        time.sleep(1)
        # OS情報
        proc = subprocess.run("uname -a",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        myOS = proc.stdout
        proc = subprocess.run("ifconfig en0 | awk '/ether/ { print $2 }' ",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        myMacAddress = proc.stdout
        self.cmdText += "\n" + proc.stdout + "\n"
        self.cmdText += "\n====================================\n"
        self.cmdText += "自端末の情報の取得が完了しました"
        self.cmdText += "\n====================================\n"

        # 自ノード情報の構成
        self.nodes.append({
            "id":"0",
            "address":myAddress,
            "macaddress":myMacAddress,
            "hostname":myHostname,
            "os":myOS,
            "service":"""不明
            """,
            "type":"self"
        })

        # 自ネットワークの情報取得
        # proc = subprocess.Popen("nmap -sP 192.168.1.0/24",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        proc = subprocess.Popen("arp -a",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.cmdText += "\n====================================\n"
        self.cmdText += "ネットワークスキャン中..."

        # self.ids["left_box"].ids["load_img"].source = "images/loading/load6.gif" # セグフォ吐くんでコメントアウト　なんで？

        try:
            outs, errs = proc.communicate(timeout=60)
            print(outs.splitlines())
            self.loadingFlag = False
            self.cmdText += "\n====================================\n"
            self.cmdText += outs
            self.cmdText += "\n====================================\n"
            self.cmdText += "ネットワークのスキャンが完了しました"
            self.cmdText += "\n====================================\n"

            # ip情報抜き出し
            PATTERN =r'[0-9]+(?:\.[0-9]+){3}'
            ipList = re.findall( PATTERN, outs )
            # macアドレス情報抜き出し
            PATTERN =r'((([0-9a-fA-F]{1,2}:){5})[0-9a-fA-F]{2})'
            macList = re.findall( PATTERN, outs )

            print(ipList)
            print(macList)

            # ノード情報の構築
            for i in range(len(ipList)):
                self.nodes.append({
                    "id":str(i + 1),
                    "address":ipList[i],
                    "macaddress":macList[i][0],
                    "hostname":"不明",
                    "os":"不明",
                    "service":"""不明
                    """,
                    "type":"def_node"
                })
            # ネットワークのテーブルデータ構成
            # ノードの生成
            for i in range(len(self.nodes)):
                self.addNode(self.nodes[i])

            self.cmdText += "\n====================================\n"
            self.cmdText += "セットアップ完了 システムを開始します"
            self.cmdText += "\n====================================\n"

        except subprocess.SubprocessError:
            proc.kill()
            outs, errs = proc.communicate()
            self.loadingFlag = False
            self.cmdText += "\n====================================\n"
            self.cmdText += "セットアップエラー"
            self.cmdText += "\n====================================\n"
            return

    def loading(self):
        self.loadingFlag = True
        while self.loadingFlag:
            time.sleep(0.3)
            self.cmdText += "."

    # ロードウィンドウ変更
    def changeLoad(self,btn):
        self.ids["left_box"].ids["load_img"].source = "images/loading/" + btn.text + ".gif"

    # コマンド実行
    def cmdInput(self):
        cmd = self.ids["right_box"].ids["cmd_input"].text
        res = subprocess.getoutput(cmd)
        self.cmdText += "> " + cmd + "\n"
        self.cmdText += res
        self.cmdText += "\n====================================\n"
        self.ids["right_box"].ids["cmd_input"].text = ""

    # コマンドビューにフォーカスが当たった場合インプット領域にフォーカスを移す
    def changeFocus(self):
        self.ids["right_box"].ids["cmd_input"].focus = True

    # ノードの追加処理
    def addNode(self, nodes):

        networkIdentifier = self.ids["center_box"].ids["network_window"]

        x = int(random.uniform(0,networkIdentifier.width * 0.9))
        y = int(random.uniform(0,networkIdentifier.height * 0.8))

        # 画像イメージ設定(self→自分自身、def_node→デフォルトノード[危険度：グレー])
        if nodes["type"] == "self":
            image = "images/nood/pc_green.png"
            downImage = "images/nood/pc_red.png"
        else:
            image = "images/nood/pc_gray.png"
            downImage = "images/nood/pc_red.png"

        layout = ScatterLayout(scale=0.2, x=x + 400, y=y)
        button = ToggleButton(
            size_hint_y=0.8,
            group="noods",
            text=nodes["id"],
            font_size="0",
            on_release=self.nodeCheck,size_hint=(0.4, 0.7),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
            background_normal=image,
            background_down=downImage,
            )
        label = Label(
            size_hint_y=0.2,
            text=nodes["address"],
            font_size="150",
            halign="left"
        )
        boxLayout = BoxLayout(orientation="vertical")
        boxLayout.add_widget(button)
        boxLayout.add_widget(label)
        layout.add_widget(boxLayout)
        networkIdentifier.add_widget(layout)

    #  ノード選択時
    def nodeCheck(self, btn):
        self.mainWindow.address = "IPアドレス：" + self.nodes[int(btn.text)]["address"]
        self.mainWindow.macaddress = "MACアドレス：" + self.nodes[int(btn.text)]["macaddress"]
        self.mainWindow.hostName = "ホストネーム：" + self.nodes[int(btn.text)]["hostname"]
        self.mainWindow.OS = "OS：" + self.nodes[int(btn.text)]["os"]
        self.mainWindow.service = "稼働サービス：" + self.nodes[int(btn.text)]["service"]

    # メインウィンドウメニュー選択時
    def changeMainWindow(self,data):
        self.ids["center_box"].ids["main_window"].clear_widgets()
        #基本情報
        if data == 0:
            self.ids["center_box"].ids["main_window"].add_widget(self.infoWindow)
        elif data == 1:
            self.ids["center_box"].ids["main_window"].add_widget(self.networkWindow)
        elif data == 2:
            self.ids["center_box"].ids["main_window"].add_widget(self.databaseWindow)
        elif data == 3:
            self.ids["center_box"].ids["main_window"].add_widget(self.webWindow)
        elif data == 4:
            self.ids["center_box"].ids["main_window"].add_widget(self.vulnWindow)

    # でばっぐよう
    def hoge(self):
        for key, val in self.ids.items():
            print("key={0}, val={1}".format(key, val))

    def getInfo(self):
        print(self.info_data.address)

class PentestApp(App):
    def __init__(self, **kwargs):
        super(PentestApp, self).__init__(**kwargs)
        self.title = 'Pentest'

if __name__ == '__main__':
    PentestApp().run()
