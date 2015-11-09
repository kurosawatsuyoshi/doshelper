# mod_doshelper
_分散配置_された Apache Webサーバ環境で、DoS攻撃を回避するモジュールです  
apache module that protects a 'distributed web server' from DoS attack  

## Description
アクセス数が一定の閾値を超えた場合、IP単位で自動的にアクセスを遮断します  
アクセス管理は Redis を採用しています  
共有メモリ方式では無いため複数のウェブサーバを配置する分散環境でもアクセス状態を一元管理するので、急なサーバ増減でも閾値を見直す必要がありません  
なお Redis に問題が生じた場合、全アクセスをスルーする仕組みなので万一の場合も安心してご利用いただけます  
If the number of access has exceeded a certain threshold, it will automatically stop by IP access management that employs a Redis.  
  
This is not a shared memory system.  
Since centralized management of access state in a distributed web server environment, there is no need to review the threshold even in steep increase or decrease server.  
  
If redis are experiencing problems, because to allow all access, you can use it with confidence even.  

## Features
- 複数のウェブサーバでアクセス情報を一元管理  
  The centralized management of access information by multiple web server.  
- 遮断結果のログ出力  
  Blocking results are error log output.  
- IP単位で即時遮断  
  Immediately shut off by the IP input.

ログ出力結果から攻撃を検知し、攻撃者のIPを恒久的に遮断できます  
その際の即時IP遮断はブラウザからウェブサーバのリスタート無しで複数サーバに一度にセットできます  
このようにサイト運用の効率化・軽減化を目的としています  
You can from the browser permanently block the attacker's IP Address.  
Restart of the web server is not required.  
It is the purpose in efficiency of site operations.  

## Requirement
導入に必要な要件です  
- [hiredis](https://github.com/redis/hiredis)
- apxs
- [Redis](http://redis.io/)  Redis version >= 2.4.0.  
- apache 2.0 - 2.4 prefork

## Preparation
ビルドにあたり事前のセットアップが必要です  

### hiredis
Redis接続ライブラリです  
This is Redis connection library.
```
$ wget -O hiredis.zip https://github.com/redis/hiredis/archive/master.zip
$ unzip hiredis.zip
$ cd hiredis-master/
$ make
$ sudo make install
```

### apxs
apacheモジュールのコンパイル・リンクに必要なツールです  
It is a tool necessary to compile and link the apache module  
  
_[CentOS/Fedora]_
```
$ sudo yum install httpd-devel
```

_[Debian/Ubuntu]_
```
$ sudo apt-get install apache2-prefork-dev
```

### Redis
doshelper動作時に必要です  
専用サーバ導入が望ましいのですが、DBサーバやウェブサーバへ同居でも構いません  
なおDMZ（ウェブサーバ同居）配置の場合は、IP制限などのセキュア対策が必要なため、後述のAppendix「Redis設定」を参照してください  
[Redis](http://redis.io/) is an open source (BSD licensed), in-memory data structure store, used as database, cache and message broker.  

[Redisのダウンロード](http://redis.io/download)
```
$ wget http://download.redis.io/releases/redis-2.8.23.tar.gz
$ tar xzf redis-2.8.*.tar.gz
$ cd redis-2.8.*
$ make
$ sudo make install
```

## Installation
### mod_doshelper
```
$ ./configure
$ make
$ sudo make install
```

## Configuration
設定ファイルのサンプルです  
配布ソースの"sample"ディレクトリに格納しています  
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

各設定項目の詳細となります  
It becomes the details of each configuration item.  

***
__DoshelperAction__  
doshelperを有効にする場合は on をセットします  
Set the on if you want to enable the doshelper.  

書式：on or off  
デフォルト：off  
記載例：  
```
DoshelperAction  on
```
***

__DoshelperRedisServer__  
redisサーバを指定します ※ 空白区切りで複数のRedisサーバが指定できます  
Specify the redis server ※ You can specify multiple Redis server separated by spaces.  
  
書式：サーバ名:ポート （サーバ名:ポート）  
デフォルト：なし  
記載例：  
```
DoshelperRedisServer  localhost:6379  localhost:6380
```
***

__DoshelperRedisConnectTimeout__  
redisコネクトのタイムアウトを指定します。 応答速度にあわせ調整可能です  
Specify a time-out of redis connect. It is adjustable according to the response speed.  
  
書式：秒 (空白) マイクロ秒  
デフォルト：0.05ミリ秒  
記述例：  
```
DoshelperRedisConnectTimeout  0  050000
```
***

__DoshelperRedisRequirepass__  
redis接続パスワードを指定します  
Specify the redis connection password.  
  
書式：文字列  
デフォルト：なし  
記述例：  
```
DoshelperRedisRequirepass  tiger
```
***

__DoshelperRedisDatabase__  
16個のデータベース領域（デフォルト）で利用するデータベース領域を数値で指定します  
Specify a numeric value database area to be used by 16 of the database area (default).  
  
書式：数値（0〜15）  
デフォルト：0  
記述例：  
```
DoshelperRedisDatabase  0
```
***

__DoshelperIgnoreContentType__  
処理対象外とするコンテントタイプを指定します  
Specify the content type to be excluded.  
  
書式：文字列 ※ 複数指定時はパイプ（｜）文字で連結します  
デフォルト：なし  
記述例：  
```
DoshelperIgnoreContentType  (javascript|image|css|flash|x-font-ttf)
```
***

### Setting of the DoS pattern
DoS攻撃とみなす閾値を設定します  
Sets a threshold regarded as the DoS attack.  

#### Apply to the entire site
サイト全体に適用する  
  
***
__DoshelperCommmonDosAction__  
サイト全体に適用する場合 on を指定します  
Specify the on if that apply to the entire site.  
  
書式：on or off  
デフォルト：off  
記述例：  
```
DoshelperCommmonDosAction  on
```
***

__DoshelperDosCheckTime__  
__DoshelperDosRequest__  
__DoshelperDosWaitTime__  
サイト全体に適用する遮断の閾値を設定します  
Specify the threshold that applies to the entire site.  
  
書式：数値  
デフォルト：なし  
記述例：  
30秒間に同一IPから10回のリクエストで、60秒間遮断するケース  
60 Seconds Shut-out at 10 Requests to 30 Seconds.  
```
DoshelperDosCheckTime  30
DoshelperDosRequest    10
DoshelperDosWaitTime   60
```
***

#### Apply to the URL
URL単位で適用する  

***
__DoshelperDosCase__  
URL単位で遮断するケースで利用します  
defense of the DoS of url unit.  

書式：ctime="チェックする秒" request="リクエスト回数" wtime="遮断時間（秒）"  
デフォルト：なし  
記述例：  
"/foo/bar.php"に対して5秒間に3回以上のリクエストで120秒遮断するケース  
"/foo/bar.php" is, 120 Seconds Shut-out at 3 Requests to 5 Seconds.  
```
DoshelperDosCase "^/foo/bar.php" ctime="5" request="3" wtime="120"
```
  
"/cgi-bin/hoge/"のディレクトリ配下に対し、10秒間に15回以上のリクエストで5秒遮断するケース  
"/cgi-bin/hoge/" is, 5 Seconds Shut-out at 15 Requests to 10 Seconds.  
```
DoshelperDosCase "^/cgi-bin/hoge/" ctime="10" request="15" wtime="5"
```
***

### Setting of the block pattern
レスポンスコード返却、または遮断画面表示の選択が可能です  
Select the "return the specific response code" or "cut-off screen".  
  
***
__DoshelperReturnType__  
遮断時のレスポンスコードを指定します  
Specify a response code at the time of cut-off.  
  
書式：レスポンスコード  
デフォルト：なし  
記述例：  
```
DoshelperReturnType  403
```
***

__DoshelperDosFilePath__  
事前に用意したHTMLを遮断時に表示させます（DoshelperReturnTypeと併用はできません）  
apacheユーザ（またはグループ）の参照権限を付与してください  
Display the HTML at the time of cut-off.  
"DoshelperReturnType" and combined it can not.  
Please give the reference authority in apache.  
  
書式：フルパス名  
デフォルト：なし  
記述例：  
```
DoshelperDosFilePath  /var/www/doshelper/control/dos.html
```
***

### Setting of the ip control
現在のアクセス状況の確認や、特定のIPを無条件遮断ができる管理画面の指定です  
Specify a management screen.  
Can be IP blocking and confirmed of access status.  
  
__DoshelperControlAction__  
IP即時遮断画面の利用有無を指定します  
Specify the use of IP immediate cut-off screen.  
  
書式：on or off  
デフォルト：off  
記述例：  
```
DoshelperControlAction  on
```
***

__DoshelperIpWhiteList__  
__DoshelperIpWhiteSet__  
__DoshelperIpWhiteDel__  
__DoshelperIpBlackList__  
__DoshelperIpBlackSet__  
__DoshelperIpBlackDel__  
__DoshelperControlFree__  
__DoshelperDisplayCount__  
  
管理画面のURLとアクセス時に遮断適用外とさせる期間（秒）、一覧表示させる件数を指定します  
ここで指定したパスで管理画面にアクセスするので、存在しない かつ セキュリティ観点からもわかりにくいパスを指定してください  

書式：パス名　※ ドキュメントルート以下  
デフォルト：なし  
記述例：  
```
DoshelperIpWhiteList  "/whitelist"
DoshelperIpWhiteSet   "/whitelistset"
DoshelperIpWhiteDel   "/whitelistdelete"
DoshelperIpBlackList  "/blacklist"
DoshelperIpBlackSet   "/blacklistset"
DoshelperIpBlackDel   "/blacklistdelete"
DoshelperControlFree  60
DoshelperDisplayCount 100
```
管理画面のアクセス方法  
```
http://example.com/blacklist
```
***

__DoshelperIpSetFormFilePath__  
__DoshelperIpCompleteFilePath__  
__DoshelperIpListFilePath__  
  
管理画面のテンプレートファイルです  
This is the template file management screen.  

外部に公開されない（ドキュメントルート外）に配置し、フルパスで記述してください  
apacheユーザ（またはグループ）の参照権限を付与してください  

書式：フルパス名  
デフォルト：なし  
記述例；  
```
DoshelperIpSetFormFilePath /var/www/doshelper/control/setform.html
DoshelperIpCompleteFilePath /var/www/doshelper/control/complete.html
DoshelperIpListFilePath  /var/www/doshelper/control/list.html
```
***

### Setting of the log
以下の環境変数に遮断情報がセットされます  
DoS認定時、通常のアクセス情報に加えて "DoSAttack"の文字列とリクエスト回数を”doshelper_log”として出力します  
***
DH_DOS：DoS認定された場合、"DoSAttack"の文字列がセットされます  
DH_CNT：リクエスト回数がセットされます  
***
記述例：  
```
 LogFormat  "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D %T %p \"%{DH_DOS}e\" \"%{DH_CNT}e\"" doshelper_doslog  
 CustomLog "/var/log/httpd/doshelper_log" doshelper_doslog env=DH_DOS  
```
出力例：  
```
IP - - [07/Nov/2015:18:44:17 +0900] "GET / HTTP/1.1" 200 1160 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0" 11475 0 80 "DoSAttack" "11"
IP - - [07/Nov/2015:18:44:17 +0900] "GET / HTTP/1.1" 200 1160 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0" 12060 0 80 "DoSAttack" "12"
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

以降、記述予定（2015/11/8)
