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
　サーバ追加による閾値の見直しが不要　
- 遮断結果のログ出力  
　攻撃を検知することで初動対処を早めることが可能  
　遮断結果より恒久的なIP遮断を設定できます  
- IP即時遮断  
　ウェブサーバのリスタート不要でセット可能  

## Requirement

- ![Redis2.8](http://redis.io/)
- ![hiredis](https://github.com/redis/hiredis)

## Install
