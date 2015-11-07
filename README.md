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

## Install
### hiredis
Redis接続ライブラリ  
標準は /usr/local/lib/ に導入します
```
$ wget -O hiredis.zip https://github.com/redis/hiredis/archive/master.zip
$ unzip hiredis.zip
$ cd hiredis-master/
$ make
$ make install
```

導入先変更時は、Makefile を編集してください
```
$ vi Makefile
$PREFIX?=/usr/local 　→　 PREFIX?=/home/hoge/lib
```

パッケージ導入が可能な場合は以下を参考にしてください  
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
apacheモジュールのコンパイル・リンクに必要です  

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
専用サーバへの導入が望ましいのですが、DBサーバやウェブサーバへ同居でも構いません  
DMZへの配置（ウェブサーバ同居）時は、アクセス元IPの制限などのセキュア対策が必要です  

[redisダウンロード](http://redis.io/download)からバージョン2.4以上をダウンロードします  
下記コマンドでは、wget を利用していますがブラウザからダウンロードしても構いません
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

### doshelper
```
$ ./configure
$ make
$ sudo make install
$ ls -l /etc/httpd/module/mod_doshelper.so
```

