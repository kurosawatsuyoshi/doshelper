# mod_doshelper
_分散配置_された Apache Webサーバ環境で、DoS攻撃を回避するモジュールです  
apache module that protects a 'distributed web server' from DoS attack  

## Description
アクセス数が一定の閾値を超えた場合、IP単位で自動的にアクセスを遮断します  
アクセス管理は共有メモリ方式ではなく Redis を採用しているため、複数の分散ウェブサーバ環境でも情報を一元管理しています  
急なウェブサーバ増減でも閾値を見直す必要がないため、サイト運用の軽減化がはかれます  
なお Redis に問題が生じた場合は、すべてのアクセスをスルーする仕組みとしているため万一の場合も安心してご利用いただけます  

## Features
- 複数のウェブサーバでアクセス情報を一元管理  
- 遮断結果のログ出力  
- IP単位で即時遮断  

ウェブサーバを追加しても閾値の見直しは不要です  
遮断ログから攻撃検知の予測したり、攻撃者のIPを恒久的に遮断することも可能です  
またウェブサーバのリスタートなしにブラウザからの指定で即時にIP遮断もできます  

## Requirement
- [hiredis](https://github.com/redis/hiredis)
- apxs
- [Redis](http://redis.io/)  Redis version >= 2.4.0.  

## Preparation
ビルドにあたり事前のセットアップが必要です  

### hiredis
Redis接続ライブラリでビルド時に必要となります  
```
$ wget -O hiredis.zip https://github.com/redis/hiredis/archive/master.zip
$ unzip hiredis.zip
$ cd hiredis-master/
$ make
$ sudo make install
```

### apxs
apacheモジュールのコンパイル・リンクに必要なツールです  
_[CentOS/Fedora]_
```
$ sudo yum install httpd-devel
```
_[Debian/Ubuntu]_
```
$ sudo apt-get install apache2-prefork-dev
```

### Redis
doshelperの動作時に必要です  
専用サーバへの導入が望ましいのですが、DBサーバやウェブサーバへ同居でも構いません  
なおDMZ配置（ウェブサーバ同居）の場合は、アクセス元IPを制限するなどのセキュア対策が必要です  
その他、詳細な設定方法後述のAppendix 「Redis設定」を参照してください  
[redisダウンロード](http://redis.io/download)
```
$ wget http://download.redis.io/releases/redis-2.8.23.tar.gz
$ tar xzf redis-2.8.*.tar.gz
$ cd redis-2.8.*
$ make
$ sudo make install
```

## Installation
### doshelper
```
$ ./configure
$ make
$ sudo make install
```

## Configuration
サンプルの設定ファイルです  
配布ソースの"sample"ディレクトリに設定ファイルおよび各種テンプレートファイルを格納していますので参考にしてください  
An sample configuration for mod_doshelper.  
```
LoadModule setenvif_module modules/mod_setenvif.so
<IfModule mod_setenvif.c>
# doshelper Ignore
SetEnvIf User-Agent "(DoCoMo|UP.Browser|KDDI|J-PHONE|Vodafone|SoftBank)" DOSHELPER_IGNORE
SetEnvIf Request_URI "\.(htm|html|js|css|gif|jpg|png)$" DOSHELPER_IGNORE
SetEnvIf Remote_Addr "(192.168.0.0/16|172.16.168.0/31|10.0)" DOSHELPER_IGNORE
# SetEnvIf Request_URI "^/foo/bar/" DOSHELPER_IGNORE
# SetEnvIf Request_URI "^/hoge/hoge.php" DOSHELPER_IGNORE
</IfModule>

LoadModule doshelper_module  modules/mod_doshelper.so
<IfModule mod_doshelper.c>
DoshelperAction on

DoshelperRedisServer localhost:6379
# DoshelperRedisConnectTimeout 0 50000
# DoshelperRedisRequirepass tiger
# DoshelperRedisDatabase 0

DoshelperIgnoreContentType (javascript|image|css|flash|x-font-ttf)

## defense of the DoS of web site
## 60 Seconds Shut-out at 10 Requests to 30 Seconds 
DoshelperCommmonDosAction on
DoshelperDosCheckTime  30
DoshelperDosRequest    10
DoshelperDosWaitTime   60

## defense of the DoS of url unit
## 120 Seconds Shut-out at 3 Requests to 5 Seconds 
DoshelperDosCase "^/foo/bar.php" ctime="5" request="3" wtime="120"
## 5 Seconds Shut-out at 15 Requests to 10 Seconds 
DoshelperDosCase "^/cgi-bin/hoge/" ctime="10" request="15" wtime="5"

## setting of the return code or block screen
DoshelperReturnType 403
#DoshelperDosFilePath /var/www/doshelper/control/dos.html

# setting of the ip control
DoshelperControlAction off
# uri
DoshelperIpWhiteList  "/whitelist"
DoshelperIpWhiteSet   "/whitelistset"
DoshelperIpWhiteDel   "/whitelistdelete"
DoshelperIpBlackList  "/blacklist"
DoshelperIpBlackSet   "/blacklistset"
DoshelperIpBlackDel   "/blacklistdelete"
DoshelperControlFree  60
DoshelperDisplayCount 100
# template file
DoshelperIpSetFormFilePath /var/www/doshelper/control/setform.html
DoshelperIpCompleteFilePath /var/www/doshelper/control/complete.html
DoshelperIpListFilePath  /var/www/doshelper/control/list.html

</IfModule>

# setting of the log
LogFormat  "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D %T %p \"%{DH_DOS}e\" \"%{DH_CNT}e\"" doshelper_doslog
CustomLog "/var/log/httpd/doshelper_log" doshelper_doslog env=DH_DOS
```

各項目の詳細です  
  
__DoshelperAction__  
doshelperを有効にする場合は on をセットします  
書式：on or off  
デフォルト：off  
記載例：DoshelperAction  on  
  
__DoshelperRedisServer__  
redisサーバを指定します ※ 空白区切りで複数サーバ指定  
書式：サーバ名:ポート （サーバ名:ポート）  
デフォルト：なし  
記載例：DoshelperRedisServer  localhost:6379  localhost:6380  
  
__DoshelperRedisConnectTimeout__  
redisコネクトのタイムアウトを指定します  
応答が遅い場合はこの時間で調整できます  
書式：秒 (空白) マイクロ秒  
デフォルト：0.05ミリ秒  
記述例：DoshelperRedisConnectTimeout  0  050000  
  
__DoshelperRedisRequirepass__  
redis接続パスワードを指定します  
書式：文字列  
デフォルト：なし  
記述例：DoshelperRedisRequirepass  tiger  
  
__DoshelperRedisDatabase__  
redisはデフォルトで16個のデータベース領域を確保します  
利用するデータベース領域を数値で指定します  
書式：数値（0〜15）  
デフォルト：0  
記述例：DoshelperRedisDatabase  0  
  
__DoshelperIgnoreContentType__
処理対象外とするコンテントタイプが指定できます  
SetEnvIfの拡張子除外と合わせて活用します  
書式：文字列 ※ 複数指定時はパイプ（｜）文字で連結します  
デフォルト：なし  
記述例：DoshelperIgnoreContentType  (javascript|image|css|flash|x-font-ttf)  

### Setting of the DoS pattern
DoS攻撃とみなす閾値の設定となります  
サイト全体への適用ケースとURL単位に適用するケースが設定できます  

__DoshelperCommmonDosAction__
サイト全体に適用する閾値を利用する場合 on を指定します  
書式：on or off  
デフォルト：off  
記述例：DoshelperCommmonDosAction  on  
  
__DoshelperDosCheckTime__  
__DoshelperDosRequest__  
__DoshelperDosWaitTime__  
遮断対象の閾値を指定します  
書式：数値  
デフォルト：なし  
記述例：30秒間に同一IPから10回のリクエストで、60秒間遮断するケース  
       60 Seconds Shut-out at 10 Requests to 30 Seconds.  
DoshelperDosCheckTime  30  
DoshelperDosRequest    10  
DoshelperDosWaitTime   60  
  
__DoshelperDosCase__  
URL単位で閾値を設定する場合に利用します  
defense of the DoS of url unit.  
書式：ctime="チェックする秒" request="リクエスト回数" wtime="遮断時間（秒）"  
デフォルト：なし  
記述例：  
"/foo/bar.php"に対して5秒間に3回以上のリクエストで120秒遮断するケース  
"/foo/bar.php" is, 120 Seconds Shut-out at 3 Requests to 5 Seconds.  
DoshelperDosCase "^/foo/bar.php" ctime="5" request="3" wtime="120"  
  
"/cgi-bin/hoge/"のディレクトリ配下のURLに対し、10秒間に15回以上のリクエストで5秒遮断するケース  
"/cgi-bin/hoge/" is, 5 Seconds Shut-out at 15 Requests to 10 Seconds.  
DoshelperDosCase "^/cgi-bin/hoge/" ctime="10" request="15" wtime="5"  
  
### Setting of the block pattern
特定のレスポンスコードを返却するケースと、遮断画面を表示させるケースが選択できます  
please select the "return the specific response code" or "cut-off screen".  
  
__DoshelperReturnType__
遮断時のレスポンスコードを指定します  
書式：レスポンスコード  
デフォルト：なし  
記述例：DoshelperReturnType  403  

__DoshelperDosFilePath__  
遮断時に事前に用意したHTMLを表示させることができます  
アクセス元IPなど一部の情報も表示させることができます  
なお配置したファイルとディレクトリには、apacheユーザ（またはグループ）で参照できる権限を付与してください  
書式：フルパス名  
デフォルト：なし  
記述例：DoshelperDosFilePath  /var/www/doshelper/control/dos.html  
  
### Setting of the ip control
現在のアクセス状況の確認や、特定のIPを無条件遮断ができる管理画面の指定です  

__DoshelperControlAction__
IP即時遮断画面（管理画面）の利用有無を指定します  
書式：on or off
デフォルト：off
記述例：DoshelperControlAction  on
  
__DoshelperIpWhiteList__
__DoshelperIpWhiteSet__
__DoshelperIpWhiteDel__
__DoshelperIpBlackList__
__DoshelperIpBlackSet__
__DoshelperIpBlackDel__
__DoshelperControlFree__
__DoshelperDisplayCount__
管理画面のURLとアクセス時に遮断適用外とさせる期間（秒）、一覧表示させる件数を指定します  
指定したパスで管理画面にアクセスするため、既存サイトに存在しないパス かつ セキュリティ観点からもわかりにくいパスを指定してください  
書式：パス名　※ ドキュメントルート以下  
デフォルト：なし  
記述例：  
DoshelperIpWhiteList  "/whitelist"  
DoshelperIpWhiteSet   "/whitelistset"  
DoshelperIpWhiteDel   "/whitelistdelete"  
DoshelperIpBlackList  "/blacklist"  
DoshelperIpBlackSet   "/blacklistset"  
DoshelperIpBlackDel   "/blacklistdelete"  
DoshelperControlFree  60  
DoshelperDisplayCount 100  

__DoshelperIpSetFormFilePath__
__DoshelperIpCompleteFilePath__
__DoshelperIpListFilePath__
管理画面のテンプレートファイルになります  
外部公開されない（ドキュメントルート以外）に配置し、フルパスで記述してください  
配置したファイルとディレクトリには、apacheユーザ（またはグループ）で参照できる権限を付与してください  
書式：フルパス名  
デフォルト：なし  
記述例；  
DoshelperIpSetFormFilePath /var/www/doshelper/control/setform.html  
DoshelperIpCompleteFilePath /var/www/doshelper/control/complete.html  
DoshelperIpListFilePath  /var/www/doshelper/control/list.html  
  
### Setting of the log
以下の環境変数に遮断情報がセットされます  
ログ出力で ¥%{***}e のパラメータで出力することができます  
DH_DOS：DoS認定された場合、"DoSAttack"の文字列がセットされます  
DH_CNT：リクエスト回数がセットされます  
記述例：DoS認定時、通常のアクセス情報に加えて "DoSAttack"の文字列とリクエスト回数を”doshelper_log”として出力します  
LogFormat  "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D %T %p \"%{DH_DOS}e\" \"%{DH_CNT}e\"" doshelper_doslog  
CustomLog "/var/log/httpd/doshelper_log" doshelper_doslog env=DH_DOS  
```
IP - - [07/Nov/2015:18:44:17 +0900] "GET / HTTP/1.1" 200 1160 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0" 11475 0 80 __"DoSAttack" "11"__
IP - - [07/Nov/2015:18:44:17 +0900] "GET / HTTP/1.1" 200 1160 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0" 12060 0 80 __"DoSAttack" "12"__
```

#Appendix
## hiredisのパッケージ導入
CentOSでは hiredis のパッケージ導入が可能です  
_[CentOS 7]_
```
$ wget http://dl.fedoraproject.org/pub/epel/7/x86_64/h/hiredis-0.12.1-1.el7.x86_64.rpm
$ wget http://dl.fedoraproject.org/pub/epel/7/x86_64/h/hiredis-devel-0.12.1-1.el7.x86_64.rpm
$ sudo rpm -ivh hiredis-0.12.1-1.el7.x86_64.rpm
$ sudo rpm -ivh hiredis-devel-0.12.1-1.el7.x86_64.rpm
```

_[CentOS 6]_  
導入にはepelリポジトリが必要です
```
sudo yum install --enablerepo=epel hiredis hiredis-devel
```

## Redis設定
- ユーザとグループの作成
- 設定ファイルの編集
- 自動起動設定

Redis ユーザとグループの作成
```
$ sudo groupadd redis
$ sudo useradd -s /sbin/nologin -M -g redis redis
```
