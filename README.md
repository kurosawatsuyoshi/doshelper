# doshelper
_分散配置_された Apache Webサーバ環境で、DoS攻撃を回避するモジュールです  

apache module that protects a 'distributed web server' from DoS attack  

## Description
ウェブアクセスが閾値を超えたらIP単位で自動遮断します  
アクセス管理に Redis を採用しているため、共有メモリ方式とは違い複数のウェブサーバ環境でも閾値を見直す必要がありません  

## Features
- 複数のウェブサーバでアクセス情報を一元管理  
- 遮断結果のログ出力  
- IP即時遮断  

急にウェブサーバを追加しても閾値の見直しは不要です  
遮断結果ログから攻撃検知や攻撃IPの恒久遮断をセット可能です  
ウェブサーバのリスタート不要で即時にIP遮断ができます  

## Requirement

- [hiredis](https://github.com/redis/hiredis)
- apxs
- [Redis](http://redis.io/) 2.4.0 以上
  Redis version >= 2.4.0.  

## Preparation
### hiredis
Redis接続ライブラリ
```
$ wget -O hiredis.zip https://github.com/redis/hiredis/archive/master.zip
$ unzip hiredis.zip
$ cd hiredis-master/
$ make
$ sudo make install
```

標準では /usr/local/lib/ に導入されますが、変更する場合は Makefile を編集します
```
$ vi Makefile
$PREFIX?=/usr/local 　→　 PREFIX?=/home/hoge/lib
```

なおパッケージ導入が可能な場合は、以下を参考にしてください  
_[CentOS 7]_
```
$ wget http://dl.fedoraproject.org/pub/epel/7/x86_64/h/hiredis-0.12.1-1.el7.x86_64.rpm
$ wget http://dl.fedoraproject.org/pub/epel/7/x86_64/h/hiredis-devel-0.12.1-1.el7.x86_64.rpm
$ sudo rpm -ivh hiredis-0.12.1-1.el7.x86_64.rpm
$ sudo rpm -ivh hiredis-devel-0.12.1-1.el7.x86_64.rpm
```

_[CentOS 6]_  
epelリポジトリが必要です
```
sudo yum install --enablerepo=epel hiredis hiredis-devel
```

### apxs
apacheモジュールのコンパイル・リンクに必要となります  
_[CentOS]_
```
$ sudo yum install httpd-devel
```
_[Debian]_
```
$ sudo apt-get install apache2-prefork-dev
```

### Redis
doshelperの動作時に必要です  
専用サーバが望ましいのですが、DBサーバやウェブサーバへの同居でも構いません  
なおDMZ配置（ウェブサーバ同居）の場合は、アクセス元IPを制限するなどのセキュア対策が必要です  

下記コマンドでは、wget を利用していますが[redisダウンロード](http://redis.io/download)にアクセスしダウンロードでも構いません
```
$ wget http://download.redis.io/releases/redis-2.8.23.tar.gz
$ tar xzf redis-2.8.*.tar.gz
$ cd redis-2.8.*
$ make
$ sudo make install
```
Redis ユーザとグループの作成
```
$ sudo groupadd redis
$ sudo useradd -s /sbin/nologin -M -g redis redis
```

## Installation
### doshelper
```
$ ./configure
$ make
$ sudo make install
```

## Configuration
__DoshelperAction__  
default [off]  
doshelperの有効・無効を指定します  
利用する際には on をセットしてください  

__DoshelperRedisServer__  
redisサーバを指定 ※空白区切りで複数サーバの指定が可能  
書式：サーバ名:ポート （サーバ名:ポート）
デフォルト：なし  
記載例：localhost:6379  

__DoshelperRedisConnectTimeout__  
redisコネクトの待ち時間を指定  
書式：秒 ミリ秒  
デフォルト：0.5ミリ秒  
記述例：0 50000  

__DoshelperRedisRequirepass__
redis接続パスワードを指定  
tiger
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

