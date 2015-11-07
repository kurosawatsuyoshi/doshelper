# doshelper
apache module that protects a 'distributed web server' from DoS attack  
_分散配置_された Apache Webサーバ環境で、DoS攻撃を回避するモジュールです  

## Description
It manages the web access in the IP unit, and automatic shut-off Once beyond the threshold.  
This is an Apache module to avoid the high-load site.  
By KVS (Redis) to the access management, and a mechanism for sharing the access information in a plurality of web servers.  
ウェブアクセスをIP単位で管理し、閾値を超えたら自動遮断することで、サイトの高負荷を回避するApacheモジュールです。  
アクセス管理にKVS（Redis）することで、複数のウェブサーバでもアクセス情報を共有できる仕組みにしています。  

## Features
- 複数のウェブサーバでアクセス情報を一元管理  
　サーバ追加でも閾値見直しは不要　
- 遮断結果のログ出力  
　攻撃を検知し対処の初動を早期化
　遮断結果よりIPの恒久遮断対応
- IP即時遮断  
　ウェブサーバのリスタートなく即時遮断  

## Requirement

- ![hiredis](https://github.com/redis/hiredis)
- apxs
- ![Redis](http://redis.io/)

### hiredis
Redis接続ライブラリ
    $ wget -O hiredis.zip https://github.com/redis/hiredis/archive/master.zip
    $ unzip hiredis.zip
    $ cd hiredis-master/
    $ make
    $ make install
  
標準では /usr/local/lib/ に導入されます。  
インストール先を変更する場合は、Makefile を下記のように編集してください
    $ vi Makefile
    $PREFIX?=/usr/local 　→　 PREFIX?=/home/coco/local

### Redis
アクセス情報を一元管理するデータベース（KVS）でバージョンは 2.4.0 以上をサポートします。  
Redis version >= 2.4.0.  
  
doshelper動作時に必要です。  
導入先は専用サーバが望ましいのですが、DBサーバやウェブサーバへ同居でも構いません。  
その際（DMZ配置）は、アクセス元IPを制限するなどのセキュア化が必要です。
  
導入は
    $ sudo yum install redis
    $ redis-server -v
	$ sudo chkconfig add redis
    $ sudo /etc/init.d/redis start
yumで導入できない

### apxs


## Install
