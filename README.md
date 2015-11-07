# doshelper
_分散配置_された Apache Webサーバ環境で、DoS攻撃を回避するモジュールです  

apache module that protects a 'distributed web server' from DoS attack  

## Description
ウェブアクセスが閾値を超えたらIP単位で自動遮断します  
アクセス管理に Redis を採用しているため、共有メモリ方式とは違い複数のウェブサーバ環境でも閾値を見直す必要がありません  

## Features
- 複数のウェブサーバでアクセス情報を一元管理  
　急なウェブサーバの追加でも閾値の見直しは不要です  
- 遮断結果のログ出力  
　攻撃を検知することで初動を早めることができます  
　遮断結果から攻撃IPを恒久的に遮断できます  
- IP即時遮断  
　特定のIPをセットすることで即時遮断ができます  
  ウェブサーバのリスタートは不要です

## Requirement

- [hiredis](https://github.com/redis/hiredis)
- apxs
- [Redis](http://redis.io/)
  バージョンは 2.4.0 以上をサポート    
  Redis version >= 2.4.0.  

## Install
### hiredis (Redis接続ライブラリ)
```
$ wget -O hiredis.zip https://github.com/redis/hiredis/archive/master.zip
$ unzip hiredis.zip
$ cd hiredis-master/
$ make
$ make install
```

/usr/local/lib/ に導入されます  
インストール先を変更する場合は、Makefile を編集が必要です  
```
$ vi Makefile
$PREFIX?=/usr/local 　→　 PREFIX?=/home/coco/local
```

パッケージ導入の場合は以下となります。  
_[CentOS 7]_  
```
$ wget http://dl.fedoraproject.org/pub/epel/7/x86_64/h/hiredis-0.12.1-1.el7.x86_64.rpm
$ wget http://dl.fedoraproject.org/pub/epel/7/x86_64/h/hiredis-devel-0.12.1-1.el7.x86_64.rpm
$ sudo rpm -ivh hiredis-0.12.1-1.el7.x86_64.rpm
$ sudo rpm -ivh hiredis-devel-0.12.1-1.el7.x86_64.rpm
```

_[CentOS 6]_  
epelリポジトリが必要です。  
```
sudo yum install --enablerepo=epel hiredis hiredis-devel
```

### apxs
モジュールのコンパイルに必要です  

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
